#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_M72A7_StaticInfo

#include "Basic.hpp"

#include "BP_GenericWeapon_StaticInfo_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_M72A7_StaticInfo.BP_M72A7_StaticInfo_C
// 0x0000 (0x0D88 - 0x0D88)
class UBP_M72A7_StaticInfo_C final : public UBP_GenericWeapon_StaticInfo_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_M72A7_StaticInfo_C">();
	}
	static class UBP_M72A7_StaticInfo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_M72A7_StaticInfo_C>();
	}
};
static_assert(alignof(UBP_M72A7_StaticInfo_C) == 0x000008, "Wrong alignment on UBP_M72A7_StaticInfo_C");
static_assert(sizeof(UBP_M72A7_StaticInfo_C) == 0x000D88, "Wrong size on UBP_M72A7_StaticInfo_C");

}

