#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Vz61

#include "Basic.hpp"

#include "BP_Weapon2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Vz61.BP_Vz61_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_Vz61_C : public ABP_Weapon2_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Vz61_C">();
	}
	static class ABP_Vz61_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Vz61_C>();
	}
};
static_assert(alignof(ABP_Vz61_C) == 0x000010, "Wrong alignment on ABP_Vz61_C");
static_assert(sizeof(ABP_Vz61_C) == 0x0009A0, "Wrong size on ABP_Vz61_C");

}

