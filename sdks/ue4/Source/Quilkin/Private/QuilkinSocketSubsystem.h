#pragma once

#include "CoreMinimal.h"
#include "SocketSubsystem.h"

#define QUILKIN_SOCKETSUBSYSTEM_NAME TEXT("Quilkin")

class FQuilkinSocketSubsystem : public ISocketSubsystem
{
public:
	FQuilkinSocketSubsystem(ISocketSubsystem* WrappedSocketSubsystem);
	virtual ~FQuilkinSocketSubsystem();

	//~ Begin ISocketSubsystem Interface
	virtual bool Init(FString& Error) override;
	virtual void Shutdown() override;
	virtual FSocket* CreateSocket(const FName& SocketType, const FString& SocketDescription, const FName& ProtocolName) override;
	virtual void DestroySocket(FSocket* Socket) override;
	virtual FAddressInfoResult GetAddressInfo(const TCHAR* HostName, const TCHAR* ServiceName = nullptr, EAddressInfoFlags QueryFlags = EAddressInfoFlags::Default, const FName ProtocolTypeName = NAME_None, ESocketType SocketType = ESocketType::SOCKTYPE_Unknown) override;
	virtual TSharedPtr<FInternetAddr> GetAddressFromString(const FString& InAddress) override;
	virtual bool RequiresChatDataBeSeparate() override;
	virtual bool RequiresEncryptedPackets() override;
	virtual bool GetHostName(FString& HostName) override;
	virtual TSharedRef<FInternetAddr> CreateInternetAddr() override;
	virtual bool HasNetworkDevice() override;
	virtual const TCHAR* GetSocketAPIName() const override;
	virtual ESocketErrors GetLastErrorCode() override;
	virtual ESocketErrors TranslateErrorCode(int32 Code) override;
	virtual bool IsSocketWaitSupported() const override;
	//~ End ISocketSubsystem Interface

protected:
	ISocketSubsystem* SocketSubsystem;
};
