#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BritUtilTruck_LastingEffect

#include "Basic.hpp"

#include "BP_LastingEffect_Vehicle_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BritUtilTruck_LastingEffect.BP_BritUtilTruck_LastingEffect_C
// 0x0000 (0x0288 - 0x0288)
class ABP_BritUtilTruck_LastingEffect_C final : public ABP_LastingEffect_Vehicle_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BritUtilTruck_LastingEffect_C">();
	}
	static class ABP_BritUtilTruck_LastingEffect_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BritUtilTruck_LastingEffect_C>();
	}
};
static_assert(alignof(ABP_BritUtilTruck_LastingEffect_C) == 0x000008, "Wrong alignment on ABP_BritUtilTruck_LastingEffect_C");
static_assert(sizeof(ABP_BritUtilTruck_LastingEffect_C) == 0x000288, "Wrong size on ABP_BritUtilTruck_LastingEffect_C");

}

