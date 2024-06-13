#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_T62_Turret

#include "Basic.hpp"

#include "BP_GenericVehicleClosedTurret_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_T62_Turret.BP_T62_Turret_C
// 0x0010 (0x04E0 - 0x04D0)
class ABP_T62_Turret_C final : public ABP_GenericVehicleClosedTurret_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x04D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_T62_Turret_C">();
	}
	static class ABP_T62_Turret_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_T62_Turret_C>();
	}
};
static_assert(alignof(ABP_T62_Turret_C) == 0x000010, "Wrong alignment on ABP_T62_Turret_C");
static_assert(sizeof(ABP_T62_Turret_C) == 0x0004E0, "Wrong size on ABP_T62_Turret_C");
static_assert(offsetof(ABP_T62_Turret_C, SQArmorMesh) == 0x0004D0, "Member 'ABP_T62_Turret_C::SQArmorMesh' has a wrong offset!");

}

