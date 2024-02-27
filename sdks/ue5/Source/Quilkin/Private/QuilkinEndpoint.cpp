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

#include "QuilkinEndpoint.h"

#include "Interfaces/IPv4/IPv4Address.h"
#include "QuilkinSocketSubsystem.h"

const TResult<TSharedRef<FInternetAddr>, ResolveError>
FQuilkinEndpoint::ToInternetAddr(FQuilkinSocketSubsystem* SocketSubsystem) const
{
	return ToInternetAddrBase(SocketSubsystem, Host, TrafficPort);
}

const TResult<TSharedRef<FInternetAddr>, ResolveError>
FQuilkinEndpoint::ToQcmpInternetAddr(FQuilkinSocketSubsystem* SocketSubsystem) const
{
	return ToInternetAddrBase(SocketSubsystem, Host, QcmpPort);
}

const TResult<TSharedRef<FInternetAddr>, ResolveError>
FQuilkinEndpoint::ToInternetAddrBase(FQuilkinSocketSubsystem* SocketSubsystem, FString InHost, uint16 Port) const
{
	const FName Name = FName();
	TSharedRef<FInternetAddr> Addr = SocketSubsystem->CreateInternetAddr(Name);

	FIPv4Address IPv4Address;
	if (FIPv4Address::Parse(*InHost, IPv4Address))
	{
		Addr->SetIp(IPv4Address.Value);
	}
	else
	{
		bool Resolved;
		Addr->SetIp(*InHost, Resolved);

		if (!Resolved)
		{
			ResolveError Error = {};
			return TResult<TSharedRef<FInternetAddr>, ResolveError>(Error);
		}
	}

	Addr->SetPort(Port);
	return TResult<TSharedRef<FInternetAddr>, ResolveError>(Addr);
}

