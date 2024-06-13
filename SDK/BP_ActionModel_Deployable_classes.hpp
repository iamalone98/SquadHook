#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ActionModel_Deployable

#include "Basic.hpp"

#include "SQDeployableEntry_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "BP_RadialActionModel_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_ActionModel_Deployable.BP_ActionModel_Deployable_C
// 0x00C0 (0x0168 - 0x00A8)
class UBP_ActionModel_Deployable_C final : public UBP_RadialActionModel_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_ActionModel_Deployable_C;        // 0x00A8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FSQAvailabilityState_Deployable        DeployableState;                                   // 0x00B0(0x0050)(Edit, BlueprintVisible, Transient, ContainsInstancedReference, ExposeOnSpawn)
	struct FSQDeployableEntry                     DeployableEntry;                                   // 0x0100(0x0068)(Edit, BlueprintVisible, Transient, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_ActionModel_Deployable(int32 EntryPoint);
	void OnClicked(class UBaseRadialMenu_C* Radial);
	void Open_Voice_Model();

	void GetCost(bool* Out_Has_Cost, TArray<struct FSQCostEntry>* Out_Cost) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_ActionModel_Deployable_C">();
	}
	static class UBP_ActionModel_Deployable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_ActionModel_Deployable_C>();
	}
};
static_assert(alignof(UBP_ActionModel_Deployable_C) == 0x000008, "Wrong alignment on UBP_ActionModel_Deployable_C");
static_assert(sizeof(UBP_ActionModel_Deployable_C) == 0x000168, "Wrong size on UBP_ActionModel_Deployable_C");
static_assert(offsetof(UBP_ActionModel_Deployable_C, UberGraphFrame_BP_ActionModel_Deployable_C) == 0x0000A8, "Member 'UBP_ActionModel_Deployable_C::UberGraphFrame_BP_ActionModel_Deployable_C' has a wrong offset!");
static_assert(offsetof(UBP_ActionModel_Deployable_C, DeployableState) == 0x0000B0, "Member 'UBP_ActionModel_Deployable_C::DeployableState' has a wrong offset!");
static_assert(offsetof(UBP_ActionModel_Deployable_C, DeployableEntry) == 0x000100, "Member 'UBP_ActionModel_Deployable_C::DeployableEntry' has a wrong offset!");

}
