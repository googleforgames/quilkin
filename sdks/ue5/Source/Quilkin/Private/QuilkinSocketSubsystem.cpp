/*
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "QuilkinSocketSubsystem.h"
#include "QuilkinControlMessageProtocol.h"
#include "QuilkinCircularBuffer.h"
#include "QuilkinDelegates.h"
#include "QuilkinSocket.h"
#include "QuilkinLog.h"
#include "QuilkinSettings.h"
#include "Async/Async.h"
#include "Async/ParallelFor.h"
#include "IPAddress.h"
#include "Engine/GameInstance.h"
#include "Runtime/Online/HTTP/Public/Http.h"
#include "GenericPlatform/GenericPlatformMath.h"

static int64 NowSeconds() {
	return FDateTime::UtcNow().ToUnixTimestamp();
}

FQuilkinSocketSubsystem::FQuilkinSocketSubsystem(ISocketSubsystem* WrappedSocketSubsystem) 
	: PingSocket{nullptr}
	, SocketSubsystem{WrappedSocketSubsystem}
{
	FQueuedThreadPool* ThreadPool = FQueuedThreadPool::Allocate();
	int32 NumThreads = FGenericPlatformMath::Max(FPlatformMisc::NumberOfCores() / 2, 2);
	if (!ThreadPool->Create(NumThreads, 8 * 1024)) {
		UE_LOG(LogQuilkin, Error, TEXT("Couldn't allocate thread pool"));
	}
	this->PingThreadPool = ThreadPool;
}

FQuilkinSocketSubsystem::~FQuilkinSocketSubsystem()
{
}

bool FQuilkinSocketSubsystem::Init(FString& Error)
{
	UE_LOG(LogQuilkin, Display, TEXT("Initialising Socket Subsystem"));
	PingSocket = CreateRawSocket(TEXT("QuilkinPingSocket"));
	FQuilkinDelegates::GetQuilkinEndpointMeasurements.BindRaw(this, &FQuilkinSocketSubsystem::GetEndpointMeasurements);
	FQuilkinDelegates::GetLowestLatencyEndpoint.BindRaw(this, &FQuilkinSocketSubsystem::GetLowestLatencyEndpoint);
	FQuilkinDelegates::GetLowestLatencyEndpointInRegion.BindRaw(this, &FQuilkinSocketSubsystem::GetLowestLatencyEndpointInRegion);
	FQuilkinDelegates::GetLowestLatencyToDatacenters.BindRaw(this, &FQuilkinSocketSubsystem::GetLowestLatencyToDatacenters);

	return true;
}

void FQuilkinSocketSubsystem::Shutdown()
{
	if (PingSocket != nullptr)
	{
		PingSocket = nullptr;
	}

	if (UQuilkinConfigSubsystem::IsAvailable()) {
		auto Config = UQuilkinConfigSubsystem::Get();
		if (!Config->OnEndpointsChanged.IsBound()) {
			Config->OnEndpointsChanged.Remove(UpdateEndpointHandle);
		}
	}

	if (FQuilkinDelegates::GetLowestLatencyEndpoint.IsBound()) {
		FQuilkinDelegates::GetLowestLatencyEndpoint.Unbind();
	}

	if (FQuilkinDelegates::GetLowestLatencyEndpointInRegion.IsBound()) {
		FQuilkinDelegates::GetLowestLatencyEndpointInRegion.Unbind();
	}

	if (FQuilkinDelegates::GetLowestLatencyToDatacenters.IsBound()) {
		FQuilkinDelegates::GetLowestLatencyToDatacenters.Unbind();
	}
}

bool FQuilkinSocketSubsystem::Tick(float DeltaTime) {
	// We bind here as a "late initialisation" step, as the SocketSubsystem will be initialised before GEngine.
	if (UQuilkinConfigSubsystem::IsAvailable() && !UpdateEndpointHandle.IsValid()) {
		UpdateEndpointHandle = UQuilkinConfigSubsystem::Get()->OnEndpointsChanged.AddRaw(this, &FQuilkinSocketSubsystem::UpdateEndpoints);
	}

	if (!UQuilkinConfigSubsystem::Get()->GetMeasureEndpoints())
	{
		return true;
	}

	TickElapsed += DeltaTime;

	if (TickElapsed >= 60) {
		TickElapsed = 0;

		// If there's no internet
		if (FGenericPlatformMisc::GetNetworkConnectionType() == ENetworkConnectionType::None) {
			UE_LOG(LogQuilkin, Warning, TEXT("no internet connection available"));
			return true;
		}

		PingEndpoints();
	}

	return true;
}

TArray<TTuple<FQuilkinEndpoint, int64>> FQuilkinSocketSubsystem::GetEndpointMeasurements() {
	return Endpoints.FilterMapToArray<TTuple<FQuilkinEndpoint, int64>>([](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		auto Median = Buffer.Median();
		if (Median == 0) {
			return TOptional<TTuple<FQuilkinEndpoint, int64>>();
		}
		else {
			return TOptional<TTuple<FQuilkinEndpoint, int64>>(TTuple<FQuilkinEndpoint, int64>(Endpoint, Median));
		}
	});
}

void FQuilkinSocketSubsystem::AllocatePingSocketsForEndpoints() {
	SocketAllocationLock.Lock();

	auto EndpointLength = Endpoints.Num();
	auto PingSocketLength = PingSockets.Num();
	if (PingSocketLength < EndpointLength) {
		for (int32 i = 0; i < EndpointLength - PingSocketLength; i++) {
			auto SocketResult = CreateRandomUdpSocket();

			if (SocketResult.IsError()) {
				UE_LOG(LogQuilkin, Error, TEXT("Couldn't allocate socket, message: %s"), *SocketResult.GetError());
				SocketAllocationLock.Unlock();
				return;
			}

			PingSockets.Add(SocketResult.GetValue());
		}
	}
	else if (PingSocketLength > EndpointLength) {
		for (int32 i = 0; i < PingSocketLength - EndpointLength; i++) {
			if (!PingSockets.Pop()->Close()) {
				auto ErrorCode = GetLastErrorCode();
				FString ErrorDescription = GetSocketError(ErrorCode);
				UE_LOG(LogQuilkin, Error, TEXT("failed to close socket, code: %d, message: %s"), ErrorCode, *ErrorDescription);
			}
		}
	}

	SocketAllocationLock.Unlock();
}

void FQuilkinSocketSubsystem::UpdateEndpoints(TArray<FQuilkinEndpoint> NewEndpoints) {
	Endpoints.ResetWithKeys(NewEndpoints, [](auto Endpoint) -> CircularBuffer<int64> {
		return CircularBuffer<int64>(50);
	});

	PingEndpoints();
}

TOptional<EndpointPair> FQuilkinSocketSubsystem::GetLowestLatencyEndpoint()
{
	return GetLowestLatencyEndpointImplementation(TOptional<FString>());
}

TOptional<TTuple<FQuilkinEndpoint, int64>> FQuilkinSocketSubsystem::GetLowestLatencyEndpointInRegion(FString Region) const
{
	return GetLowestLatencyEndpointImplementation(TOptional<FString>(Region));
}

TOptional<TTuple<FQuilkinEndpoint, int64>> FQuilkinSocketSubsystem::GetLowestLatencyEndpointImplementation(TOptional<FString> Region) const
{
	if (Endpoints.IsEmpty()) {
		return TOptional<TTuple<FQuilkinEndpoint, int64>>();
	}

	bool NoMeasurements = true;
	Endpoints.ForEach([&NoMeasurements](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		if (!Buffer.IsEmpty()) {
			NoMeasurements = false;
		}
	});

	if (NoMeasurements) {
		return TOptional<TTuple<FQuilkinEndpoint, int64>>();
	}

	FQuilkinEndpoint LowestEndpoint;
	int64 LowestLatency = INT64_MAX;
	Endpoints.ForEach([&LowestEndpoint, &LowestLatency, &Region](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		int64 Median = Buffer.Median();

		// If the region has been set, and it doesn't match OR the median is zero, skip the endpoint.
		if ((Region.IsSet() && Region.GetValue() != Endpoint.Region) || Median == 0)
		{
			return;
		}

		if (Median < LowestLatency)
		{
			LowestEndpoint = Endpoint;
			LowestLatency = Median;
		}
	});

	return TOptional(TTuple<FQuilkinEndpoint, int64>(LowestEndpoint, LowestLatency));

}

TOptional<FQuilkinEndpoint> FQuilkinSocketSubsystem::GetLowestLatencyProxyToDatacenter(FString IcaoCode) const {
	TOptional<FQuilkinEndpoint> FoundEndpoint;
	int64 LowestLatency = INT64_MAX;

	Endpoints.ForEach([this, &FoundEndpoint, LowestLatency, IcaoCode](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		auto ProxyLatency = Buffer.Median();

		const TArray<FQuilkinDatacenter>* FoundEntries = Datacenters.Find(Endpoint);

		if (FoundEntries == nullptr) {
			UE_LOG(LogQuilkin, Warning, TEXT("no measured datacenters for %s"), *Endpoint.ToString());
			return;
		}

		auto FoundDatacenter = FoundEntries->FindByPredicate([IcaoCode](auto Datacenter) {
			return Datacenter.IcaoCode == IcaoCode;
		});

		if (FoundDatacenter == nullptr) {
			UE_LOG(LogQuilkin, Warning, TEXT("haven't measured %s for %s"), *IcaoCode, *Endpoint.ToString());
			return;
		}

		if (FoundEndpoint.IsSet()) {
			if (FoundDatacenter->TotalDistance(ProxyLatency) < LowestLatency) {
				FoundEndpoint = Endpoint;
			}
		}
		else {
			FoundEndpoint = Endpoint;
		}
	});

	return FoundEndpoint;
}

TMap<FString, int64> FQuilkinSocketSubsystem::GetLowestLatencyToDatacenters() const
{
	TMap<FString, int64> Map;

	Endpoints.ForEach([this, &Map](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		auto ProxyLatency = Buffer.Median();
		auto FoundDatacenters = Datacenters.Find(Endpoint);

		if (FoundDatacenters == nullptr) {
			UE_LOG(LogQuilkin, Warning, TEXT("no measured datacenters for %s"), *Endpoint.ToString());
			return;
		}

		for (auto& Datacenter : *FoundDatacenters) {
			auto FoundEntry = Map.Find(Datacenter.IcaoCode);

			if (FoundEntry == nullptr) {
				Map.Add(Datacenter.IcaoCode, Datacenter.TotalDistance(ProxyLatency));
			}
			else {
				auto TotalDistance = Datacenter.TotalDistance(ProxyLatency);
				if (*FoundEntry > TotalDistance) {
					Map.Add(Datacenter.IcaoCode, TotalDistance);
				}
			}
		}
	});

	return Map;
}

TResult<FSocket*, FString> FQuilkinSocketSubsystem::CreateRandomUdpSocket()
{
    FSocket* Socket = CreateRawSocket(TEXT("QuilkinPingSocket"));

    if (!Socket)
    {
		return TResult<FSocket*, FString>(TEXT("couldn't create ping socket"));
    }

    return TResult<FSocket*, FString>(Socket);
}

void FQuilkinSocketSubsystem::PingEndpoints() {
	static std::atomic<bool> IS_ACTIVE(false);
	if (Endpoints.IsEmpty()) {
		UE_LOG(LogQuilkin, Verbose, TEXT("no endpoints to measure"));
		return;
	}

	if (IS_ACTIVE.load()) {
		UE_LOG(LogQuilkin, Verbose, TEXT("ping task already executing"));
		return;
	}

	IS_ACTIVE.store(true);
	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [this]() {
		auto Keys = Endpoints.GetKeys();

		AllocatePingSocketsForEndpoints();

		if (PingSockets.Num() != Endpoints.Num()) {
			UE_LOG(LogQuilkin, Error, TEXT("Couldn't allocate enough sockets to measure latency"));
			IS_ACTIVE.store(false);
			return;
		}

		TArray<FAsyncTask<FPingTask>*> Tasks;
		for (int32 Index = 0; Index < Endpoints.Num(); ++Index)
		{
			auto Task = new FAsyncTask<FPingTask>(this, Keys, Index);
			Task->StartBackgroundTask(PingThreadPool);
			Tasks.Add(Task);
		}

		for (auto Task : Tasks)
		{
			Task->EnsureCompletion();
		}
		
		if (UE_LOG_ACTIVE(LogQuilkin, Verbose)) {
			auto Result = this->GetLowestLatencyEndpoint();

			if (!Result.IsSet()) {
				IS_ACTIVE.store(false);
				return;
			}

			auto Pair = Result.GetValue();
			FQuilkinEndpoint Endpoint = Pair.template Get<0>();
			UE_LOG(LogQuilkin, Verbose, TEXT("Lowest latency endpoint is %s (%dms)"), *Endpoint.ToString(), NanosToMillis(Pair.template Get<1>()));
		}

		GetDatacenterLatencies();

		if (UQuilkinConfigSubsystem::IsAvailable()) {
			auto Config = UQuilkinConfigSubsystem::Get();
			if (Config->MeasurementCompleted.IsBound()) {
				Config->MeasurementCompleted.Broadcast();
			}
		}

		IS_ACTIVE.store(false);
	});
}

TResult<int64, FString> FQuilkinSocketSubsystem::SendPing(FSocket* Socket, FInternetAddr& AddrRef)
{
	uint32 PingCount = 5;
	TArray<uint8> Nonces;
	auto Addr = AddrRef.Clone();
	Addr->SetPort(7600);

	UE_LOG(LogQuilkin, Verbose, TEXT("measuring latency to %s"), *Addr->ToString(true));

	for (uint32 i = 0; i < PingCount; i++) {
		auto Result = SendPacket(Socket, *Addr);
		if (Result.IsError()) {
			UE_LOG(LogQuilkin, Warning, TEXT("failed to send ping to %s: %s"), *Addr->ToString(true), *Result.GetError());
		}
		else {
			Nonces.Push(Result.GetValue());
		}
	}

	if (Nonces.IsEmpty()) {
		return TResult<int64, FString>(TEXT("all pings to failed"));
	}

	auto NewLatency = WaitForResponses(Socket, *Addr, PingCount, Nonces);

	if (NewLatency < 0ll)
		return TResult<int64, FString>(TEXT("exit requested"));

	UE_LOG(LogQuilkin, Verbose, TEXT("new measured latency for %s: %dms"), *Addr->ToString(true), NanosToMillis(NewLatency));
	return TResult<int64, FString>(NewLatency);
}

TResult<uint8, FString> FQuilkinSocketSubsystem::SendPacket(FSocket* Socket, FInternetAddr& Addr)
{
	auto Ping = FPing();
	auto Buffer = Ping.Encode();
	auto BytesSent = 0;
	UE_LOG(LogQuilkin, Verbose, TEXT("sending ping to %s, Nonce: %d"), *Addr.ToString(true), Ping.GetNonce());
	if (!Socket->SendTo(Buffer.GetData(), Buffer.Num(), BytesSent, Addr)) {
		auto ErrorCode = GetLastErrorCode();
		FString ErrorDescription = GetSocketError(ErrorCode);
		return TResult<uint8, FString>(ErrorDescription);
	}
	else {
		return TResult<uint8, FString>(Ping.GetNonce());
	}
}

int64 FQuilkinSocketSubsystem::WaitForResponses(FSocket* Socket, FInternetAddr& Addr, uint32 PingCount, TArray<uint8> Nonces)
{
	const double Timeout = 5.0;
	const double StartTime = NowSeconds();
	uint32 ExpectedResponses = Nonces.Num();
	int32 ExceededTimeouts = 0;
	CircularBuffer<int64> SuccessfulResponses = CircularBuffer<int64>(PingCount);

	while ((SuccessfulResponses.Num() < Nonces.Num()) && (ExceededTimeouts <= Nonces.Num()) && (NowSeconds() - StartTime < Timeout))
	{
		if (IsEngineExitRequested())
			return -1ll;

		TArray<uint8> Buffer;
		Buffer.SetNumUninitialized(1024);
		int32 BytesReceived = 0;
		UE_LOG(LogQuilkin, Verbose, TEXT("waiting on ping response from %s"), *Addr.ToString(true));
		if (Socket->Wait(ESocketWaitConditions::WaitForRead, FTimespan::FromMilliseconds(500)))
		{
			if (Socket->RecvFrom(Buffer.GetData(), Buffer.Num(), BytesReceived, Addr))
			{
				UE_LOG(LogQuilkin, Verbose, TEXT("received response from %s"), *Addr.ToString(true));
				auto Result = FPingReply::Decode(Buffer);

				if (Result.IsError()) {
					UE_LOG(LogQuilkin, Warning, TEXT("failed to decode ping reply: %s"), *Result.GetError());
					continue;
				}

				auto Packet = Result.GetValue()->AsVariant<FPingReply>();

				if (!Packet.IsSet()) {
					UE_LOG(LogQuilkin, Warning, TEXT("expected ping reply, found: %d"), Result.GetValue()->GetCode());
					continue;
				}

				auto Reply = Packet.GetValue();

				if (!Nonces.Contains(Reply->GetNonce())) {
					UE_LOG(LogQuilkin, Warning, TEXT("received nonce (%d) didn't match any sent nonce"), Reply->GetNonce());
					continue;
				}
				else {
					UE_LOG(LogQuilkin, Verbose, TEXT("received nonce (%d)"), Reply->GetNonce());
				}

				SuccessfulResponses.Add(Reply->RoundTimeDelay());
			}
		}
		else
		{
			ExceededTimeouts += 1;
			continue;
		}
	}

	if (ExceededTimeouts > 0) {
		UE_LOG(LogQuilkin, Display, TEXT("%s exceeded WaitForRead timeout %d times"), *Addr.ToString(true), ExceededTimeouts);
	}

	// If we sent less pings or we received less pings due to system errors or packet loss,
	//  then we penalise the endpoint's latency measurement for being inconsistent.
	uint32 PenaltyFactor = (PingCount - ExpectedResponses) + (ExpectedResponses - SuccessfulResponses.Num()) + ExceededTimeouts;
	for (uint32 i = 0; i < PenaltyFactor; i++) {
		SuccessfulResponses.Add(DefaultPenaltyLatency);
	}

	return SuccessfulResponses.Median();
}

void FQuilkinSocketSubsystem::GetDatacenterLatencies() {
	if (!UQuilkinConfigSubsystem::IsAvailable()) {
		UE_LOG(LogQuilkin, Display, TEXT("config subsystem unavailable, terminating GetDatacenterLatencies"));
		return;
	}

	auto Config = UQuilkinConfigSubsystem::Get();

	Endpoints.ForEach([this, &Config](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		auto LatencyInMillis = uint64(NanosToMillis(Buffer.Median()));
		if (LatencyInMillis >= Config->GetPingThresholdMillis()) {
			UE_LOG(LogQuilkin, Verbose, TEXT("Skipping %s, measured latency (%dms) > ping threshold (%dms"), *Endpoint.ToString(), LatencyInMillis, Config->GetPingThresholdMillis());
			return;
		}

		auto HttpRequest = FHttpModule::Get().CreateRequest();
		HttpRequest->SetURL(Endpoint.ToQcmpInternetAddr(this).GetValue()->ToString(true));
		HttpRequest->SetVerb("GET");
		HttpRequest->SetTimeout(0.5);

		HttpRequest->OnProcessRequestComplete().BindLambda([this, Endpoint](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bWasSuccessful) {
			if (!bWasSuccessful || !Response.IsValid())
			{
				UE_LOG(LogQuilkin, Warning, TEXT("GetDatacenters failed for %s: (was successful: %s), (response is valid: %s"), *Endpoint.ToString(), bWasSuccessful ? TEXT("true"): TEXT("false"), Response.IsValid() ? TEXT("true"): TEXT("false"));
				return;
			}

			FString JsonResponse = Response->GetContentAsString();

			TSharedPtr<FJsonObject> JsonObject;
			TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(JsonResponse);
			if (FJsonSerializer::Deserialize(Reader, JsonObject) && JsonObject.IsValid())
			{
				TArray<FQuilkinDatacenter> DatacenterArray;

				for (auto& Elem : JsonObject->Values)
				{
					double Distance;
					FString IcaoCode = Elem.Key;
					if (Elem.Value->TryGetNumber(Distance)) {
						UE_LOG(LogQuilkin, Verbose, TEXT("%s has %dms latency to %s"), *Endpoint.ToString(), NanosToMillis(std::llround(Distance)), *IcaoCode);
						DatacenterArray.Add(FQuilkinDatacenter {
							IcaoCode,
							Distance,
						});
					}
				}

				this->Datacenters.Add(Endpoint, DatacenterArray);
			}
		});

		HttpRequest->ProcessRequest();
	});
}

// MARK: ISocketSubsystem Interface

FSocket* FQuilkinSocketSubsystem::CreateSocket(const FName& SocketType, const FString& SocketDescription, bool bForceUDP) 
{ 
	return SocketSubsystem->CreateSocket(SocketType, SocketDescription, bForceUDP); 
}

FSocket* FQuilkinSocketSubsystem::CreateSocket(const FName& SocketType, const FString& SocketDescription, const FName& ProtocolName)
{
	FSocket* WrappedSocket = SocketSubsystem->CreateSocket(SocketType, SocketDescription, ProtocolName);
	if (WrappedSocket == nullptr)
	{
		UE_LOG(LogQuilkin, Warning, TEXT("CreateSocket returned nullptr"));
		return nullptr;
	}

	ESocketType InSocketType = WrappedSocket->GetSocketType();
	auto Socket = new FQuilkinSocket(FUniqueSocket(WrappedSocket), InSocketType, SocketDescription, ProtocolName);

	Socket->Subsystem = AsWeak();
	return Socket;
}

FSocket* FQuilkinSocketSubsystem::CreateRawSocket(const FString& SocketDescription) {
	FName SocketType = NAME_DGram;
	FSocket* WrappedSocket = SocketSubsystem->CreateSocket(SocketType, SocketDescription, true);
	if (WrappedSocket == nullptr)
	{
		UE_LOG(LogQuilkin, Warning, TEXT("CreateSocket returned nullptr"));
		return nullptr;
	}

	ESocketType InSocketType = WrappedSocket->GetSocketType();
	return WrappedSocket;
};

void FQuilkinSocketSubsystem::DestroySocket(FSocket* Socket)
{
	SocketSubsystem->DestroySocket(Socket);
}

FResolveInfoCached* FQuilkinSocketSubsystem::CreateResolveInfoCached(TSharedPtr<FInternetAddr> Addr) const 
{
	return SocketSubsystem->CreateResolveInfoCached(Addr);
}

FAddressInfoResult FQuilkinSocketSubsystem::GetAddressInfo(const TCHAR* HostName, const TCHAR* ServiceName, EAddressInfoFlags QueryFlags, const FName ProtocolTypeName, ESocketType SocketType)
{
	return SocketSubsystem->GetAddressInfo(HostName, ServiceName, QueryFlags, ProtocolTypeName, SocketType);
}

void FQuilkinSocketSubsystem::GetAddressInfoAsync(FAsyncGetAddressInfoCallback Callback, const TCHAR* HostName, const TCHAR* ServiceName, EAddressInfoFlags QueryFlags, const FName ProtocolTypeName, ESocketType SocketType) 
{
	SocketSubsystem->GetAddressInfoAsync(Callback, HostName, ServiceName, QueryFlags, ProtocolTypeName, SocketType);
}

TSharedPtr<FInternetAddr> FQuilkinSocketSubsystem::GetAddressFromString(const FString& InAddress)
{
	return SocketSubsystem->GetAddressFromString(InAddress);
}

FResolveInfo* FQuilkinSocketSubsystem::GetHostByName(const ANSICHAR* HostName)
{
	return SocketSubsystem->GetHostByName(HostName);
}

bool FQuilkinSocketSubsystem::RequiresChatDataBeSeparate()
{
	return SocketSubsystem->RequiresChatDataBeSeparate();
}

bool FQuilkinSocketSubsystem::RequiresEncryptedPackets()
{
	return SocketSubsystem->RequiresEncryptedPackets();
}

bool FQuilkinSocketSubsystem::GetHostName(FString& HostName)
{
	return SocketSubsystem->GetHostName(HostName);
}

TSharedRef<FInternetAddr> FQuilkinSocketSubsystem::CreateInternetAddr()
{
	return SocketSubsystem->CreateInternetAddr();
}

TSharedRef<FInternetAddr> FQuilkinSocketSubsystem::CreateInternetAddr(const FName ProtocolType)
{
	return SocketSubsystem->CreateInternetAddr(ProtocolType);
}

TSharedRef<FInternetAddr> FQuilkinSocketSubsystem::GetLocalBindAddr(FOutputDevice& Out)
{
	return SocketSubsystem->GetLocalBindAddr(Out);
}

TArray<TSharedRef<FInternetAddr>> FQuilkinSocketSubsystem::GetLocalBindAddresses()
{
	return SocketSubsystem->GetLocalBindAddresses();
}

bool FQuilkinSocketSubsystem::GetLocalAdapterAddresses(TArray<TSharedPtr<FInternetAddr>>& OutAddresses)
{
	return SocketSubsystem->GetLocalAdapterAddresses(OutAddresses);
}

TUniquePtr<FRecvMulti> FQuilkinSocketSubsystem::CreateRecvMulti(int32 MaxNumPackets, int32 MaxPacketSize, ERecvMultiFlags Flags)
{
	return SocketSubsystem->CreateRecvMulti(MaxNumPackets, MaxPacketSize, Flags);
}

TSharedRef<FInternetAddr> FQuilkinSocketSubsystem::GetLocalHostAddr(FOutputDevice& Out, bool& bCanBindAll)
{
	return SocketSubsystem->GetLocalHostAddr(Out, bCanBindAll);
}

bool FQuilkinSocketSubsystem::GetMultihomeAddress(TSharedRef<FInternetAddr>& Addr)
{
	return SocketSubsystem->GetMultihomeAddress(Addr);
}

bool FQuilkinSocketSubsystem::HasNetworkDevice()
{
	return SocketSubsystem->HasNetworkDevice();
}

const TCHAR* FQuilkinSocketSubsystem::GetSocketAPIName() const
{
	return SocketSubsystem->GetSocketAPIName();
}

ESocketErrors FQuilkinSocketSubsystem::GetLastErrorCode()
{
	return SocketSubsystem->GetLastErrorCode();
}

ESocketErrors FQuilkinSocketSubsystem::TranslateErrorCode(int32 Code)
{
	return SocketSubsystem->TranslateErrorCode(Code);
}

bool FQuilkinSocketSubsystem::IsSocketRecvMultiSupported() const
{
	return SocketSubsystem->IsSocketRecvMultiSupported();
}

bool FQuilkinSocketSubsystem::IsSocketWaitSupported() const
{
	return SocketSubsystem->IsSocketWaitSupported();
}

double FQuilkinSocketSubsystem::TranslatePacketTimestamp(const FPacketTimestamp& Timestamp, ETimestampTranslation Translation)
{
	return SocketSubsystem->TranslatePacketTimestamp(Timestamp, Translation);
}

bool FQuilkinSocketSubsystem::IsRecvFromWithPktInfoSupported() const
{
	return SocketSubsystem->IsRecvFromWithPktInfoSupported();
}
