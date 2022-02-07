#include "QuilkinPacketHandler.h"
#include "QuilkinDelegates.h"


FQuilkinPacketHandler::FQuilkinPacketHandler()
{
	if (FQuilkinDelegates::GetQuilkinRoutingToken.IsBound())
	{
		RoutingToken = FQuilkinDelegates::GetQuilkinRoutingToken.Execute();
	}
}

bool FQuilkinPacketHandler::IsEnabled()
{
	return RoutingToken.Num() > 0;
}
