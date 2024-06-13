#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ODKMulticastProvider

#include "Basic.hpp"

#include "ODKAnalyticsProvider_classes.hpp"


namespace SDK
{

// Class ODKMulticastProvider.ODKMulticastProviderConfig
// 0x0010 (0x0050 - 0x0040)
class UODKMulticastProviderConfig : public UODKAnalyticsProviderConfig
{
public:
	TArray<class FName>                           ProviderModules;                                   // 0x0040(0x0010)(ZeroConstructor, Config, NativeAccessSpecifierPublic)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKMulticastProviderConfig">();
	}
	static class UODKMulticastProviderConfig* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKMulticastProviderConfig>();
	}
};
static_assert(alignof(UODKMulticastProviderConfig) == 0x000008, "Wrong alignment on UODKMulticastProviderConfig");
static_assert(sizeof(UODKMulticastProviderConfig) == 0x000050, "Wrong size on UODKMulticastProviderConfig");
static_assert(offsetof(UODKMulticastProviderConfig, ProviderModules) == 0x000040, "Member 'UODKMulticastProviderConfig::ProviderModules' has a wrong offset!");

// Class ODKMulticastProvider.ODKMulticastProviderConfig_Dev
// 0x0000 (0x0050 - 0x0050)
class UODKMulticastProviderConfig_Dev final : public UODKMulticastProviderConfig
{
public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKMulticastProviderConfig_Dev">();
	}
	static class UODKMulticastProviderConfig_Dev* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKMulticastProviderConfig_Dev>();
	}
};
static_assert(alignof(UODKMulticastProviderConfig_Dev) == 0x000008, "Wrong alignment on UODKMulticastProviderConfig_Dev");
static_assert(sizeof(UODKMulticastProviderConfig_Dev) == 0x000050, "Wrong size on UODKMulticastProviderConfig_Dev");

}

