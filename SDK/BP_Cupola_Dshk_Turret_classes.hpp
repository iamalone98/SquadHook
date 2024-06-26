#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Cupola_Dshk_Turret

#include "Basic.hpp"

#include "BP_GenericVehicleOpenTurret_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Cupola_Dshk_Turret.BP_Cupola_Dshk_Turret_C
// 0x0010 (0x0480 - 0x0470)
class ABP_Cupola_Dshk_Turret_C final : public ABP_GenericVehicleOpenTurret_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMeshWeapon;                                 // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Cupola_Dshk_Turret_C">();
	}
	static class ABP_Cupola_Dshk_Turret_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Cupola_Dshk_Turret_C>();
	}
};
static_assert(alignof(ABP_Cupola_Dshk_Turret_C) == 0x000010, "Wrong alignment on ABP_Cupola_Dshk_Turret_C");
static_assert(sizeof(ABP_Cupola_Dshk_Turret_C) == 0x000480, "Wrong size on ABP_Cupola_Dshk_Turret_C");
static_assert(offsetof(ABP_Cupola_Dshk_Turret_C, SQArmorMeshWeapon) == 0x000470, "Member 'ABP_Cupola_Dshk_Turret_C::SQArmorMeshWeapon' has a wrong offset!");
static_assert(offsetof(ABP_Cupola_Dshk_Turret_C, SQArmorMesh) == 0x000478, "Member 'ABP_Cupola_Dshk_Turret_C::SQArmorMesh' has a wrong offset!");

}

