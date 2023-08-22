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
#include "Engine/DeveloperSettings.h"
#include "QuilkinEndpoint.h"

#include "QuilkinSettings.generated.h"

UCLASS(config = Game)
class QUILKIN_API UQuilkinDeveloperSettings : public UDeveloperSettings
{
	GENERATED_BODY()

public:
	// UDeveloperSettings overrides
	UQuilkinDeveloperSettings(const FObjectInitializer& ObjectInitializer) {};

	virtual FName GetContainerName() const { return FName("Project"); }
	virtual FName GetCategoryName() const { return FName("Plugins"); }
	virtual FName GetSectionName() const { return FName("Quilkin"); }

	// virtual FText GetSectionText() const override
	// {
	// 	return NSLOCTEXT("Quilkin", "QuilkinSettingsName", "Quilkin");
	// }

	// virtual FText GetSectionDescription() const override
	// {
	// 	return NSLOCTEXT("Quilkin", "QuilkinSettingsDescription", "Configure the Quilkin plugin");
	// }

public:

	bool IsEnabled() const {
		return Enabled && IsEnabledInEditor();
	}

	bool IsEnabledInEditor() const {
#if WITH_EDITOR
		return EnabledInPie;
#else
		return true;
#endif
	}

	/** The token used to route traffic from the proxy to the appropiate gameserver */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	TArray<uint8> RoutingToken;

	/** Whether to use Quilkin proxy routing in-game */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	bool Enabled = false;

	/** Whether to use Quilkin proxy routing in-editor */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	bool EnabledInPie = false;

	/** Whether to regularly measure each endpoint in `Endpoints`'s latency. */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	bool MeasureEndpoints = false;

	/** The amount of time (in milliseconds) that Quilkin will consider a proxy too
	  * far to be worth measuring the full datacenter latency.
	  */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	uint64 PingThresholdMillis = 185;

	/** The amount of time (in milliseconds) that Quilkin should wait before switching
	  * to the next available proxy.
	  */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	uint64 JitterThreshold = 150;

	/** List of endpoints to Quilkin proxies */
	UPROPERTY(config, EditAnywhere, Category = Settings)
	TArray<FQuilkinEndpoint> Endpoints;
};

/** Defines a property and a delegate for that property, and provides a getter
  * which will call the delegate if bound, otherwise will call the primitive property.
  */
#define DECLARE_PROPERTY_AND_DELEGATE(Type, PropName) \
    private: \
		UPROPERTY(EditAnywhere, Category = "Quilkin") \
        Type PropName; \
    public: \
        DECLARE_DELEGATE_RetVal(Type, F##PropName##BindingDelegate); \
        F##PropName##BindingDelegate PropName##Binding; \
        DECLARE_MULTICAST_DELEGATE_OneParam(F##PropName##ChangedDelegate, Type); \
        F##PropName##ChangedDelegate On##PropName##Changed; \
    public: \
        Type Get##PropName() \
        { \
            if (PropName##Binding.IsBound()) \
            { \
                return PropName##Binding.Execute(); \
            } \
            else \
            { \
                return PropName; \
            } \
        } \
        void Set##PropName(Type Value) \
        { \
			checkf(! PropName##Binding.IsBound(), TEXT("Cannot call Set##PropName with PropName##Binding set.")); \
			PropName = Value; \
			if (On##PropName##Changed.IsBound()) { \
				On##PropName##Changed.Broadcast(PropName); \
			} \
        }


UCLASS()
class QUILKIN_API UQuilkinConfigSubsystem : public UEngineSubsystem
{
    GENERATED_BODY()

    UQuilkinConfigSubsystem() {
		UE_LOG(LogQuilkin, Display, TEXT("Initialising UQuilkinConfigSubsystem"));
        const UQuilkinDeveloperSettings* DefaultSettings = GetDefault<UQuilkinDeveloperSettings>();
        Enabled = DefaultSettings->IsEnabled();
		RoutingToken = DefaultSettings->RoutingToken;
		MeasureEndpoints = DefaultSettings->MeasureEndpoints;
		PingThresholdMillis = DefaultSettings->PingThresholdMillis;
		JitterThreshold = DefaultSettings->JitterThreshold;
		Endpoints = DefaultSettings->Endpoints;
    }

	virtual void Deinitialize() override {
		UE_LOG(LogQuilkin, Display, TEXT("Tearing down UQuilkinConfigSubsystem"));
	}

public:
	static bool IsAvailable() {
		return GEngine != nullptr && GEngine->GetEngineSubsystem<UQuilkinConfigSubsystem>() != nullptr;
	}

	static UQuilkinConfigSubsystem* Get() {
		checkf(GEngine != nullptr, TEXT("UQuilkinConfigSubsystem can only be called inside an Engine context"));
		UQuilkinConfigSubsystem* Subsystem = GEngine->GetEngineSubsystem<UQuilkinConfigSubsystem>();
		checkf(Subsystem != nullptr, TEXT("UQuilkinConfigSubsystem hasn't been initialised"));
		return Subsystem;
	}

	/** Whether sockets should add routing tokens to packets */
	UPROPERTY(EditAnywhere, Category = "Quilkin")
    bool PacketHandling;

	DECLARE_PROPERTY_AND_DELEGATE(bool, Enabled);
	DECLARE_PROPERTY_AND_DELEGATE(bool, MeasureEndpoints);
	DECLARE_PROPERTY_AND_DELEGATE(uint64, PingThresholdMillis);
	DECLARE_PROPERTY_AND_DELEGATE(TArray<uint8>, RoutingToken);
	DECLARE_PROPERTY_AND_DELEGATE(TArray<FQuilkinEndpoint>, Endpoints);

	UPROPERTY(EditAnywhere, Category = "Quilkin")
	uint64 JitterThreshold;

	DECLARE_MULTICAST_DELEGATE(FMeasurementCompletedDelegate);
	FMeasurementCompletedDelegate MeasurementCompleted;
};

