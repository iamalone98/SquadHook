#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GPMG

#include "Basic.hpp"

#include "BP_GenericVehicleOpenTurretWeapon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GPMG.BP_GPMG_C
// 0x0000 (0x0D40 - 0x0D40)
class ABP_GPMG_C final : public ABP_GenericVehicleOpenTurretWeapon_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GPMG_C">();
	}
	static class ABP_GPMG_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GPMG_C>();
	}
};
static_assert(alignof(ABP_GPMG_C) == 0x000010, "Wrong alignment on ABP_GPMG_C");
static_assert(sizeof(ABP_GPMG_C) == 0x000D40, "Wrong size on ABP_GPMG_C");

}
