#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_I_Sandbag_murder_hole

#include "Basic.hpp"

#include "BP_Deployable_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_I_Sandbag_murder_hole.BP_I_Sandbag_murder_hole_C
// 0x0038 (0x0478 - 0x0440)
class ABP_I_Sandbag_murder_hole_C : public ABP_Deployable_C
{
public:
	class UStaticMeshComponent*                   SM_SandbagCamo_Interior;                           // 0x0440(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   SM_SandbagCamo_Exterior;                           // 0x0448(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Sandbag_wall_hole_v2;                              // 0x0450(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          InteractZone;                                      // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Sandbag_wall_stakes;                               // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Sandbag_wall_hole_mid;                             // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          Box;                                               // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_I_Sandbag_murder_hole_C">();
	}
	static class ABP_I_Sandbag_murder_hole_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_I_Sandbag_murder_hole_C>();
	}
};
static_assert(alignof(ABP_I_Sandbag_murder_hole_C) == 0x000008, "Wrong alignment on ABP_I_Sandbag_murder_hole_C");
static_assert(sizeof(ABP_I_Sandbag_murder_hole_C) == 0x000478, "Wrong size on ABP_I_Sandbag_murder_hole_C");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, SM_SandbagCamo_Interior) == 0x000440, "Member 'ABP_I_Sandbag_murder_hole_C::SM_SandbagCamo_Interior' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, SM_SandbagCamo_Exterior) == 0x000448, "Member 'ABP_I_Sandbag_murder_hole_C::SM_SandbagCamo_Exterior' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, Sandbag_wall_hole_v2) == 0x000450, "Member 'ABP_I_Sandbag_murder_hole_C::Sandbag_wall_hole_v2' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, InteractZone) == 0x000458, "Member 'ABP_I_Sandbag_murder_hole_C::InteractZone' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, Sandbag_wall_stakes) == 0x000460, "Member 'ABP_I_Sandbag_murder_hole_C::Sandbag_wall_stakes' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, Sandbag_wall_hole_mid) == 0x000468, "Member 'ABP_I_Sandbag_murder_hole_C::Sandbag_wall_hole_mid' has a wrong offset!");
static_assert(offsetof(ABP_I_Sandbag_murder_hole_C, Box) == 0x000470, "Member 'ABP_I_Sandbag_murder_hole_C::Box' has a wrong offset!");

}

