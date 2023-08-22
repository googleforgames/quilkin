/*
 * Copyright 2024 Google LLC
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
#include "QuilkinCircularBuffer.h"
#include "../Public/QuilkinEndpoint.h"
#include "IPAddress.h"

class QUILKIN_API FQuilkinInternetAddrs : public FInternetAddr {
public:
	//~ Start FInternetAddr overrides
	virtual void SetIp(uint32 InAddr) override;
	virtual void SetIp(const TCHAR* InAddr, bool& bIsValid) override;

	//~ End FInternetAddr overrides

	TOptional<EndpointPair> GetLowestLatencyEndpoint();

private:
	TSConcurrentMap<FQuilkinEndpoint, CircularBuffer<int64>> Endpoints;
};
