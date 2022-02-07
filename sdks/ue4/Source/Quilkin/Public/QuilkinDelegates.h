#pragma once

#include "CoreMinimal.h"
#include "UObject/ObjectMacros.h"
#include "UObject/UObjectGlobals.h"
#include "UObject/Object.h"

class QUILKIN_API FQuilkinDelegates
{
public:
	/**
	 * Delegate used to retrieve the client's proxy routing token if
	 * connection takes place via a proxy.
	 *
	 * @return The client's routing token to use.
	 */
	DECLARE_DELEGATE_RetVal(TArray<uint8>, FGetQuilkinRoutingToken);
	static FGetQuilkinRoutingToken GetQuilkinRoutingToken;
};
