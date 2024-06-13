#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ODKAnalyticsProvider

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"


namespace SDK
{

// Class ODKAnalyticsProvider.ODKAnalyticsProviderConfig
// 0x0018 (0x0040 - 0x0028)
class UODKAnalyticsProviderConfig : public UObject
{
public:
	int32                                         BatchSize;                                         // 0x0028(0x0004)(ZeroConstructor, Config, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	int32                                         RetryLimit;                                        // 0x002C(0x0004)(ZeroConstructor, Config, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
	TArray<class FName>                           EventFilters;                                      // 0x0030(0x0010)(ZeroConstructor, Config, NativeAccessSpecifierPrivate)

public:
	static class UClass* StaticClass()
	{
		return StaticClassImpl<"ODKAnalyticsProviderConfig">();
	}
	static class UODKAnalyticsProviderConfig* GetDefaultObj()
	{
		return GetDefaultObjImpl<UODKAnalyticsProviderConfig>();
	}
};
static_assert(alignof(UODKAnalyticsProviderConfig) == 0x000008, "Wrong alignment on UODKAnalyticsProviderConfig");
static_assert(sizeof(UODKAnalyticsProviderConfig) == 0x000040, "Wrong size on UODKAnalyticsProviderConfig");
static_assert(offsetof(UODKAnalyticsProviderConfig, BatchSize) == 0x000028, "Member 'UODKAnalyticsProviderConfig::BatchSize' has a wrong offset!");
static_assert(offsetof(UODKAnalyticsProviderConfig, RetryLimit) == 0x00002C, "Member 'UODKAnalyticsProviderConfig::RetryLimit' has a wrong offset!");
static_assert(offsetof(UODKAnalyticsProviderConfig, EventFilters) == 0x000030, "Member 'UODKAnalyticsProviderConfig::EventFilters' has a wrong offset!");

}

