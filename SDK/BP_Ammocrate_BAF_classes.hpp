#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ammocrate_BAF

#include "Basic.hpp"

#include "BP_GenericAmmocrate_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Ammocrate_BAF.BP_Ammocrate_BAF_C
// 0x0028 (0x0488 - 0x0460)
class ABP_Ammocrate_BAF_C final : public ABP_GenericAmmocrate_C
{
public:
	class UChildActorComponent*                   ThreeDIcon;                                        // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh19;                                      // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh16;                                      // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh26;                                      // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          ConstructionBox;                                   // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Ammocrate_BAF_C">();
	}
	static class ABP_Ammocrate_BAF_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Ammocrate_BAF_C>();
	}
};
static_assert(alignof(ABP_Ammocrate_BAF_C) == 0x000008, "Wrong alignment on ABP_Ammocrate_BAF_C");
static_assert(sizeof(ABP_Ammocrate_BAF_C) == 0x000488, "Wrong size on ABP_Ammocrate_BAF_C");
static_assert(offsetof(ABP_Ammocrate_BAF_C, ThreeDIcon) == 0x000460, "Member 'ABP_Ammocrate_BAF_C::ThreeDIcon' has a wrong offset!");
static_assert(offsetof(ABP_Ammocrate_BAF_C, StaticMesh19) == 0x000468, "Member 'ABP_Ammocrate_BAF_C::StaticMesh19' has a wrong offset!");
static_assert(offsetof(ABP_Ammocrate_BAF_C, StaticMesh16) == 0x000470, "Member 'ABP_Ammocrate_BAF_C::StaticMesh16' has a wrong offset!");
static_assert(offsetof(ABP_Ammocrate_BAF_C, StaticMesh26) == 0x000478, "Member 'ABP_Ammocrate_BAF_C::StaticMesh26' has a wrong offset!");
static_assert(offsetof(ABP_Ammocrate_BAF_C, ConstructionBox) == 0x000480, "Member 'ABP_Ammocrate_BAF_C::ConstructionBox' has a wrong offset!");

}

