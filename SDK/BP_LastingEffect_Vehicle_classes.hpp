#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_LastingEffect_Vehicle

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_LastingEffect_Vehicle.BP_LastingEffect_Vehicle_C
// 0x0000 (0x0288 - 0x0288)
class ABP_LastingEffect_Vehicle_C : public ASQLastingEffect
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_LastingEffect_Vehicle_C">();
	}
	static class ABP_LastingEffect_Vehicle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_LastingEffect_Vehicle_C>();
	}
};
static_assert(alignof(ABP_LastingEffect_Vehicle_C) == 0x000008, "Wrong alignment on ABP_LastingEffect_Vehicle_C");
static_assert(sizeof(ABP_LastingEffect_Vehicle_C) == 0x000288, "Wrong size on ABP_LastingEffect_Vehicle_C");

}

