#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ural_375_Logi_MIL

#include "Basic.hpp"

#include "BP_Ural_375_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Ural_375_Logi_MIL.BP_Ural_375_Logi_MIL_C
// 0x0010 (0x0C20 - 0x0C10)
class ABP_Ural_375_Logi_MIL_C : public ABP_Ural_375_C
{
public:
	class UStaticMeshComponent*                   SupplyDecoration;                                  // 0x0C10(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	bool                                          Initialized;                                       // 0x0C18(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Ural_375_Logi_MIL_C">();
	}
	static class ABP_Ural_375_Logi_MIL_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Ural_375_Logi_MIL_C>();
	}
};
static_assert(alignof(ABP_Ural_375_Logi_MIL_C) == 0x000010, "Wrong alignment on ABP_Ural_375_Logi_MIL_C");
static_assert(sizeof(ABP_Ural_375_Logi_MIL_C) == 0x000C20, "Wrong size on ABP_Ural_375_Logi_MIL_C");
static_assert(offsetof(ABP_Ural_375_Logi_MIL_C, SupplyDecoration) == 0x000C10, "Member 'ABP_Ural_375_Logi_MIL_C::SupplyDecoration' has a wrong offset!");
static_assert(offsetof(ABP_Ural_375_Logi_MIL_C, Initialized) == 0x000C18, "Member 'ABP_Ural_375_Logi_MIL_C::Initialized' has a wrong offset!");

}

