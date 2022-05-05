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
