/*
 * Copyright 2022 Google LLC
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

#include "QuilkinSocket.h"

FQuilkinSocket::FQuilkinSocket(FUniqueSocket WrappedSocket, ESocketType InSocketType, const FString& InSocketDescription, const FName& InSocketProtocol)
	: FSocket(InSocketType, InSocketDescription, InSocketProtocol)
	, Socket{MoveTemp(WrappedSocket)}
	, Handler{}
{
}

FQuilkinSocket::~FQuilkinSocket()
{
}

bool FQuilkinSocket::Shutdown(ESocketShutdownMode Mode)
{
	return Socket.Get()->Shutdown(Mode);
}

bool FQuilkinSocket::Close()
{
	return Socket.Get()->Close();
}

bool FQuilkinSocket::Bind(const FInternetAddr& Addr)
{
	return Socket.Get()->Bind(Addr);
}

bool FQuilkinSocket::Connect(const FInternetAddr& Addr)
{
	return Socket.Get()->Connect(Addr);
}

bool FQuilkinSocket::Listen(int32 MaxBacklog)
{
	return Socket.Get()->Listen(MaxBacklog);
}

bool FQuilkinSocket::WaitForPendingConnection(bool& bHasPendingConnection, const FTimespan& WaitTime)
{
	return Socket.Get()->WaitForPendingConnection(bHasPendingConnection, WaitTime);
}

bool FQuilkinSocket::HasPendingData(uint32& PendingDataSize)
{
	return Socket.Get()->HasPendingData(PendingDataSize);
}

FSocket* FQuilkinSocket::Accept(const FString& InSocketDescription)
{
	return Socket.Get()->Accept(InSocketDescription);
}

FSocket* FQuilkinSocket::Accept(FInternetAddr& OutAddr, const FString& InSocketDescription)
{
	return Socket.Get()->Accept(OutAddr, InSocketDescription);
}

bool FQuilkinSocket::SendTo(const uint8* Data, int32 Count, int32& BytesSent, const FInternetAddr& Destination)
{
	if (!Handler.IsEnabled())
	{
		return Socket.Get()->SendTo(Data, Count, BytesSent, Destination);
	}

	FBitWriter Packet;
	Packet = Handler.Handle(Data, Count);
	return Socket.Get()->SendTo(Packet.GetData(), Packet.GetNumBytes(), BytesSent, Destination);
}

bool FQuilkinSocket::Send(const uint8* Data, int32 Count, int32& BytesSent)
{
	if (!Handler.IsEnabled())
	{
		return Socket.Get()->Send(Data, Count, BytesSent);
	}

	FBitWriter Packet;
	Packet = Handler.Handle(Data, Count);
	return Socket.Get()->Send(Packet.GetData(), Packet.GetNumBytes(), BytesSent);
}

bool FQuilkinSocket::RecvFrom(uint8* Data, int32 BufferSize, int32& BytesRead, FInternetAddr& Source, ESocketReceiveFlags::Type Flags)
{
	return Socket.Get()->RecvFrom(Data, BufferSize, BytesRead, Source, Flags);
}

bool FQuilkinSocket::Recv(uint8* Data, int32 BufferSize, int32& BytesRead, ESocketReceiveFlags::Type Flags)
{
	return Socket.Get()->Recv(Data, BufferSize, BytesRead, Flags);
}

bool FQuilkinSocket::Wait(ESocketWaitConditions::Type Condition, FTimespan WaitTime)
{
	return Socket.Get()->Wait(Condition, WaitTime);
}

ESocketConnectionState FQuilkinSocket::GetConnectionState()
{
	return Socket.Get()->GetConnectionState();

}

void FQuilkinSocket::GetAddress(FInternetAddr& OutAddr)
{
	return Socket.Get()->GetAddress(OutAddr);
}

bool FQuilkinSocket::GetPeerAddress(FInternetAddr& OutAddr)
{
	return Socket.Get()->GetPeerAddress(OutAddr);
}

bool FQuilkinSocket::SetNonBlocking(bool bIsNonBlocking)
{
	return Socket.Get()->SetNonBlocking(bIsNonBlocking);

}

bool FQuilkinSocket::SetBroadcast(bool bAllowBroadcast)
{
	return Socket.Get()->SetBroadcast(bAllowBroadcast);
}

bool FQuilkinSocket::SetNoDelay(bool bIsNoDelay)
{
	return Socket.Get()->SetNoDelay(bIsNoDelay);
}

bool FQuilkinSocket::JoinMulticastGroup(const FInternetAddr& GroupAddress)
{
	return Socket.Get()->JoinMulticastGroup(GroupAddress);
}

bool FQuilkinSocket::JoinMulticastGroup(const FInternetAddr& GroupAddress, const FInternetAddr& InterfaceAddress)
{
	return Socket.Get()->JoinMulticastGroup(GroupAddress, InterfaceAddress);
}

bool FQuilkinSocket::LeaveMulticastGroup(const FInternetAddr& GroupAddress)
{
	return Socket.Get()->LeaveMulticastGroup(GroupAddress);
}

bool FQuilkinSocket::LeaveMulticastGroup(const FInternetAddr& GroupAddress, const FInternetAddr& InterfaceAddress)
{
	return Socket.Get()->LeaveMulticastGroup(GroupAddress, InterfaceAddress);
}

bool FQuilkinSocket::SetMulticastLoopback(bool bLoopback)
{
	return Socket.Get()->SetMulticastLoopback(bLoopback);
}

bool FQuilkinSocket::SetMulticastTtl(uint8 TimeToLive)
{
	return Socket.Get()->SetMulticastTtl(TimeToLive);
}

bool FQuilkinSocket::SetMulticastInterface(const FInternetAddr& InterfaceAddress)
{
	return Socket.Get()->SetMulticastInterface(InterfaceAddress);
}

bool FQuilkinSocket::SetReuseAddr(bool bAllowReuse)
{
	return Socket.Get()->SetReuseAddr(bAllowReuse);
}

bool FQuilkinSocket::SetLinger(bool bShouldLinger, int32 Timeout)
{
	return Socket.Get()->SetLinger(bShouldLinger, Timeout);
}

bool FQuilkinSocket::SetRecvErr(bool bUseErrorQueue)
{
	return Socket.Get()->SetRecvErr(bUseErrorQueue);
}

bool FQuilkinSocket::SetSendBufferSize(int32 Size, int32& NewSize)
{
	return Socket.Get()->SetSendBufferSize(Size, NewSize);
}

bool FQuilkinSocket::SetReceiveBufferSize(int32 Size, int32& NewSize)
{
	return Socket.Get()->SetReceiveBufferSize(Size, NewSize);
}

int32 FQuilkinSocket::GetPortNo()
{
	return Socket.Get()->GetPortNo();
}

bool FQuilkinSocket::RecvMulti(FRecvMulti& MultiData, ESocketReceiveFlags::Type Flags)
{
	return Socket.Get()->RecvMulti(MultiData, Flags);
}

bool FQuilkinSocket::SetRetrieveTimestamp(bool bRetrieveTimestamp)
{
	return Socket.Get()->SetRetrieveTimestamp(bRetrieveTimestamp);
}

bool FQuilkinSocket::SetIpPktInfo(bool bEnable)
{
	return Socket.Get()->SetIpPktInfo(bEnable);
}

bool FQuilkinSocket::RecvFromWithPktInfo(uint8* Data, int32 BufferSize, int32& BytesRead, FInternetAddr& Source, FInternetAddr& Destination, ESocketReceiveFlags::Type Flags)
{
	return Socket.Get()->RecvFromWithPktInfo(Data, BufferSize, BytesRead, Source, Destination, Flags);
}
