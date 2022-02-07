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
