#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BM21_INS_Destroyed

#include "Basic.hpp"

#include "BP_GenericDestroyedVehicleWreck_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BM21_INS_Destroyed.BM21_INS_Destroyed_C
// 0x0008 (0x03C8 - 0x03C0)
class ABM21_INS_Destroyed_C final : public ABP_GenericDestroyedVehicleWreck_C
{
public:
	class UStaticMeshComponent*                   CollisionMesh;                                     // 0x03C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BM21_INS_Destroyed_C">();
	}
	static class ABM21_INS_Destroyed_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABM21_INS_Destroyed_C>();
	}
};
static_assert(alignof(ABM21_INS_Destroyed_C) == 0x000008, "Wrong alignment on ABM21_INS_Destroyed_C");
static_assert(sizeof(ABM21_INS_Destroyed_C) == 0x0003C8, "Wrong size on ABM21_INS_Destroyed_C");
static_assert(offsetof(ABM21_INS_Destroyed_C, CollisionMesh) == 0x0003C0, "Member 'ABM21_INS_Destroyed_C::CollisionMesh' has a wrong offset!");

}
