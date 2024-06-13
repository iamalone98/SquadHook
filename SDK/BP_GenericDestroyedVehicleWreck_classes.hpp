#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDestroyedVehicleWreck

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericDestroyedVehicleWreck.BP_GenericDestroyedVehicleWreck_C
// 0x0008 (0x03C0 - 0x03B8)
class ABP_GenericDestroyedVehicleWreck_C : public ASQDestroyedVehicle
{
public:
	class UBP_WreckSplashDamageComponent_C*       BP_WreckSplashDamageComponent;                     // 0x03B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void GetPitchTurretComponent(class ASQVehicleSeat* Seat, class USQVelocityRotatingMovementComponent** Component);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericDestroyedVehicleWreck_C">();
	}
	static class ABP_GenericDestroyedVehicleWreck_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericDestroyedVehicleWreck_C>();
	}
};
static_assert(alignof(ABP_GenericDestroyedVehicleWreck_C) == 0x000008, "Wrong alignment on ABP_GenericDestroyedVehicleWreck_C");
static_assert(sizeof(ABP_GenericDestroyedVehicleWreck_C) == 0x0003C0, "Wrong size on ABP_GenericDestroyedVehicleWreck_C");
static_assert(offsetof(ABP_GenericDestroyedVehicleWreck_C, BP_WreckSplashDamageComponent) == 0x0003B8, "Member 'ABP_GenericDestroyedVehicleWreck_C::BP_WreckSplashDamageComponent' has a wrong offset!");

}
