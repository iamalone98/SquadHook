#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_AT3_Proj2

#include "Basic.hpp"

#include "BP_GenericGuidedMissileProjectile_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_AT3_Proj2.BP_AT3_Proj2_C
// 0x0000 (0x0550 - 0x0550)
class ABP_AT3_Proj2_C final : public ABP_GenericGuidedMissileProjectile_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_AT3_Proj2_C">();
	}
	static class ABP_AT3_Proj2_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_AT3_Proj2_C>();
	}
};
static_assert(alignof(ABP_AT3_Proj2_C) == 0x000008, "Wrong alignment on ABP_AT3_Proj2_C");
static_assert(sizeof(ABP_AT3_Proj2_C) == 0x000550, "Wrong size on ABP_AT3_Proj2_C");

}

