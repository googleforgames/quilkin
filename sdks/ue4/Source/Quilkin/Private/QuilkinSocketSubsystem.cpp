#include "QuilkinSocketSubsystem.h"
#include "QuilkinSocket.h"
#include "QuilkinLog.h"

FQuilkinSocketSubsystem::FQuilkinSocketSubsystem(ISocketSubsystem* WrappedSocketSubsystem) : SocketSubsystem{WrappedSocketSubsystem}
{
}

FQuilkinSocketSubsystem::~FQuilkinSocketSubsystem()
{
}

bool FQuilkinSocketSubsystem::Init(FString& Error)
{
	return true;
}

void FQuilkinSocketSubsystem::Shutdown()
{
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
	return new FQuilkinSocket(FUniqueSocket(WrappedSocket), InSocketType, SocketDescription, ProtocolName);
}

void FQuilkinSocketSubsystem::DestroySocket(FSocket* Socket)
{
	SocketSubsystem->DestroySocket(Socket);
}

FAddressInfoResult FQuilkinSocketSubsystem::GetAddressInfo(const TCHAR* HostName, const TCHAR* ServiceName, EAddressInfoFlags QueryFlags, const FName ProtocolTypeName, ESocketType SocketType)
{
	return SocketSubsystem->GetAddressInfo(HostName, ServiceName, QueryFlags, ProtocolTypeName, SocketType);
}

TSharedPtr<FInternetAddr> FQuilkinSocketSubsystem::GetAddressFromString(const FString& InAddress)
{
	return SocketSubsystem->GetAddressFromString(InAddress);
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

bool FQuilkinSocketSubsystem::IsSocketWaitSupported() const
{
	return SocketSubsystem->IsSocketWaitSupported();
}
