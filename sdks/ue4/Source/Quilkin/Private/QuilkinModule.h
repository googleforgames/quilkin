#pragma once

#include "CoreMinimal.h"
#include "Modules/ModuleInterface.h"
#include "QuilkinSocketSubsystem.h"

class FQuilkinModule : public IModuleInterface
{
public:
	//~ Begin IModuleInterface interface
	virtual void StartupModule() override;
	virtual void ShutdownModule() override;
	virtual bool SupportsDynamicReloading() override;
	virtual bool SupportsAutomaticShutdown() override;
	//~ End IModuleInterface Interface

private:
	TUniquePtr<FQuilkinSocketSubsystem> QuilkinSocketSubsystem;
};
