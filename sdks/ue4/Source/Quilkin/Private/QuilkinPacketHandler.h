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

#pragma once

#include "CoreMinimal.h"

class FQuilkinPacketHandler
{
public:
	FQuilkinPacketHandler();
	bool IsEnabled();

	FORCEINLINE const FBitWriter Handle(const uint8* Packet, int32 CountBytes)
	{
		// Add the current packet version.
		uint8 PacketVersion = 0;
		int PacketVersionNumBytes = 1;

		// Reserve enough space for the token and packet version.
		FBitWriter NewPacket((CountBytes + RoutingToken.Num() + PacketVersionNumBytes) * 8, true);

		NewPacket.Serialize((void*)Packet, CountBytes);
		NewPacket.Serialize(RoutingToken.GetData(), RoutingToken.Num());
		NewPacket.Serialize(&PacketVersion, PacketVersionNumBytes);
		return NewPacket;
	}

private:
	TArray<uint8> RoutingToken;
};
