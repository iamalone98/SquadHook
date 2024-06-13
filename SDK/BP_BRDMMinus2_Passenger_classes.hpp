#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BRDMMinus2_Passenger

#include "Basic.hpp"

#include "BP_BTR_Passenger_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BRDM-2_Passenger.BP_BRDM-2_Passenger_C
// 0x0000 (0x03F0 - 0x03F0)
class ABP_BRDMMinus2_Passenger_C final : public ABP_BTR_Passenger_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BRDM-2_Passenger_C">();
	}
	static class ABP_BRDMMinus2_Passenger_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BRDMMinus2_Passenger_C>();
	}
};
static_assert(alignof(ABP_BRDMMinus2_Passenger_C) == 0x000010, "Wrong alignment on ABP_BRDMMinus2_Passenger_C");
static_assert(sizeof(ABP_BRDMMinus2_Passenger_C) == 0x0003F0, "Wrong size on ABP_BRDMMinus2_Passenger_C");

}

