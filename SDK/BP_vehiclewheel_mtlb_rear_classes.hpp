#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_vehiclewheel_mtlb_rear

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_vehiclewheel_mtlb_rear.BP_vehiclewheel_mtlb_rear_C
// 0x0000 (0x0108 - 0x0108)
class UBP_vehiclewheel_mtlb_rear_C final : public USQVehicleWheel_Tracked
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_vehiclewheel_mtlb_rear_C">();
	}
	static class UBP_vehiclewheel_mtlb_rear_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_vehiclewheel_mtlb_rear_C>();
	}
};
static_assert(alignof(UBP_vehiclewheel_mtlb_rear_C) == 0x000008, "Wrong alignment on UBP_vehiclewheel_mtlb_rear_C");
static_assert(sizeof(UBP_vehiclewheel_mtlb_rear_C) == 0x000108, "Wrong size on UBP_vehiclewheel_mtlb_rear_C");

}

