#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericVehicleOpenTurret_LockedSwivel

#include "Basic.hpp"

#include "BP_GenericVehicleOpenTurret_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericVehicleOpenTurret_LockedSwivel.BP_GenericVehicleOpenTurret_LockedSwivel_C
// 0x0010 (0x0480 - 0x0470)
class ABP_GenericVehicleOpenTurret_LockedSwivel_C : public ABP_GenericVehicleOpenTurret_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericVehicleOpenTurret_LockedSwivel_C">();
	}
	static class ABP_GenericVehicleOpenTurret_LockedSwivel_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericVehicleOpenTurret_LockedSwivel_C>();
	}
};
static_assert(alignof(ABP_GenericVehicleOpenTurret_LockedSwivel_C) == 0x000010, "Wrong alignment on ABP_GenericVehicleOpenTurret_LockedSwivel_C");
static_assert(sizeof(ABP_GenericVehicleOpenTurret_LockedSwivel_C) == 0x000480, "Wrong size on ABP_GenericVehicleOpenTurret_LockedSwivel_C");
static_assert(offsetof(ABP_GenericVehicleOpenTurret_LockedSwivel_C, SQArmorMesh) == 0x000470, "Member 'ABP_GenericVehicleOpenTurret_LockedSwivel_C::SQArmorMesh' has a wrong offset!");

}
