#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Vz61_StaticInfo

#include "Basic.hpp"

#include "BP_GenericWeapon_StaticInfo_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Vz61_StaticInfo.BP_Vz61_StaticInfo_C
// 0x0000 (0x0D88 - 0x0D88)
class UBP_Vz61_StaticInfo_C final : public UBP_GenericWeapon_StaticInfo_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Vz61_StaticInfo_C">();
	}
	static class UBP_Vz61_StaticInfo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Vz61_StaticInfo_C>();
	}
};
static_assert(alignof(UBP_Vz61_StaticInfo_C) == 0x000008, "Wrong alignment on UBP_Vz61_StaticInfo_C");
static_assert(sizeof(UBP_Vz61_StaticInfo_C) == 0x000D88, "Wrong size on UBP_Vz61_StaticInfo_C");

}

