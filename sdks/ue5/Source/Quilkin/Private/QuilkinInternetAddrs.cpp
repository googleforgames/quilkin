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

#include "QuilkinInternetAddrs.h"
#include "IPAddress.h"

TOptional<EndpointPair> FQuilkinInternetAddrs::GetLowestLatencyEndpoint() {
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
	Endpoints.ForEach([&LowestEndpoint, &LowestLatency](FQuilkinEndpoint Endpoint, CircularBuffer<int64> Buffer) {
		int64 Median = Buffer.Median();
		if (Median < LowestLatency) {
			LowestEndpoint = Endpoint;
			LowestLatency = Median;
		}
	});
	return TOptional(TTuple<FQuilkinEndpoint, int64>(LowestEndpoint, LowestLatency));
}

void FQuilkinInternetAddrs::SetIp(uint32 InAddr) {
	UE_LOG(LogQuilkin, Warning, TEXT("SetIp will no-op while Quilkin is enabled, set the available proxy endpoints through `AddAddr`"));
}

void FQuilkinInternetAddrs::SetIp(const TCHAR* InAddr, bool& bIsValid) {
	UE_LOG(LogQuilkin, Warning, TEXT("SetIp will no-op while Quilkin is enabled, set the available proxy endpoints through `AddAddr`"));
}
