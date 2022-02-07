#include "QuilkinModule.h"
#include "QuilkinLog.h"

#include "Modules/ModuleManager.h"
#include "SocketSubsystemModule.h"
#include "UObject/NameTypes.h"

void FQuilkinModule::StartupModule()
{
	UE_LOG(LogQuilkin, Log, TEXT("FQuilkinModule::StartupModule()"));

	bool bEnabled = true;
	if (GConfig)
	{
		GConfig->GetBool(TEXT("Quilkin.SocketSubsystem"), TEXT("Enabled"), bEnabled, GEngineIni);
	}
	UE_LOG(LogQuilkin, Log, TEXT("QuilkinSocketSubsystem is %s"), bEnabled ? TEXT("enabled") : TEXT("disabled"));

	if (!bEnabled)
	{
		return;
	}

	FSocketSubsystemModule& SocketSubsystemModule = FModuleManager::LoadModuleChecked<FSocketSubsystemModule>("Sockets");

	ISocketSubsystem* DefaultSocketSubsystem = SocketSubsystemModule.GetSocketSubsystem();
	if (DefaultSocketSubsystem == nullptr)
	{
		UE_LOG(LogQuilkin, Log, TEXT("No default SocketSubsystem was set. Will not use Quilkin SocketSubsystem"));
		return;
	}
	UE_LOG(LogQuilkin, Log, TEXT("Overriding default SocketSubsystem with QuilkinSocketSubsystem"));

	QuilkinSocketSubsystem = MakeUnique<FQuilkinSocketSubsystem>(DefaultSocketSubsystem);
	SocketSubsystemModule.RegisterSocketSubsystem(QUILKIN_SOCKETSUBSYSTEM_NAME, QuilkinSocketSubsystem.Get(), true);
}

void FQuilkinModule::ShutdownModule()
{
	UE_LOG(LogQuilkin, Log, TEXT("FQuilkinModule::ShutdownModule()"));

	if (!QuilkinSocketSubsystem.IsValid())
	{
		return;
	}

	FSocketSubsystemModule& SocketSubsystemModule = FModuleManager::LoadModuleChecked<FSocketSubsystemModule>("Sockets");
	SocketSubsystemModule.UnregisterSocketSubsystem(QUILKIN_SOCKETSUBSYSTEM_NAME);
	QuilkinSocketSubsystem.Reset();
}

bool FQuilkinModule::SupportsDynamicReloading()
{
	return false;
}

bool FQuilkinModule::SupportsAutomaticShutdown()
{
	// Shutdown gets called by the SocketSubsystem, if we were registered (and we don't do anything if we weren't)
	return false;
}

IMPLEMENT_MODULE(FQuilkinModule, Quilkin);
