#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDestroyedVehicleWreck_PhysTurreted

#include "Basic.hpp"

#include "BP_GenericDestroyedVehicleWreck_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericDestroyedVehicleWreck_PhysTurreted.BP_GenericDestroyedVehicleWreck_PhysTurreted_C
// 0x0020 (0x03E0 - 0x03C0)
class ABP_GenericDestroyedVehicleWreck_PhysTurreted_C : public ABP_GenericDestroyedVehicleWreck_C
{
public:
	class UParticleSystemComponent*               BarrelEffect;                                      // 0x03C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               AmmoCookEffect;                                    // 0x03C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   TurretBarrel;                                      // 0x03D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWreckTurretAmmocook*          SQVehicleWreckTurretAmmocook;                      // 0x03D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericDestroyedVehicleWreck_PhysTurreted_C">();
	}
	static class ABP_GenericDestroyedVehicleWreck_PhysTurreted_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericDestroyedVehicleWreck_PhysTurreted_C>();
	}
};
static_assert(alignof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C) == 0x000008, "Wrong alignment on ABP_GenericDestroyedVehicleWreck_PhysTurreted_C");
static_assert(sizeof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C) == 0x0003E0, "Wrong size on ABP_GenericDestroyedVehicleWreck_PhysTurreted_C");
static_assert(offsetof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C, BarrelEffect) == 0x0003C0, "Member 'ABP_GenericDestroyedVehicleWreck_PhysTurreted_C::BarrelEffect' has a wrong offset!");
static_assert(offsetof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C, AmmoCookEffect) == 0x0003C8, "Member 'ABP_GenericDestroyedVehicleWreck_PhysTurreted_C::AmmoCookEffect' has a wrong offset!");
static_assert(offsetof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C, TurretBarrel) == 0x0003D0, "Member 'ABP_GenericDestroyedVehicleWreck_PhysTurreted_C::TurretBarrel' has a wrong offset!");
static_assert(offsetof(ABP_GenericDestroyedVehicleWreck_PhysTurreted_C, SQVehicleWreckTurretAmmocook) == 0x0003D8, "Member 'ABP_GenericDestroyedVehicleWreck_PhysTurreted_C::SQVehicleWreckTurretAmmocook' has a wrong offset!");

}
