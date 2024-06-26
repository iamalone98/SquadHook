#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_InfantryRazorwire

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_InfantryRazorwire.BP_InfantryRazorwire_C.ExecuteUbergraph_BP_InfantryRazorwire
// 0x0060 (0x0060 - 0x0000)
struct BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4C23[0xC];                                     // 0x0004(0x000C)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTransform                             CallFunc_GetTransform_ReturnValue;                 // 0x0010(0x0030)(ConstParm, IsPlainOldData, NoDestructor)
	class AActor*                                 CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue; // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ARazorsinglefull_C*                     CallFunc_FinishSpawningActor_ReturnValue;          // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsGhost_ReturnValue;                      // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire) == 0x000010, "Wrong alignment on BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire");
static_assert(sizeof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire) == 0x000060, "Wrong size on BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire");
static_assert(offsetof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire, EntryPoint) == 0x000000, "Member 'BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire, CallFunc_GetTransform_ReturnValue) == 0x000010, "Member 'BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire::CallFunc_GetTransform_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire, CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue) == 0x000040, "Member 'BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire::CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire, CallFunc_FinishSpawningActor_ReturnValue) == 0x000048, "Member 'BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire::CallFunc_FinishSpawningActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire, CallFunc_IsGhost_ReturnValue) == 0x000050, "Member 'BP_InfantryRazorwire_C_ExecuteUbergraph_BP_InfantryRazorwire::CallFunc_IsGhost_ReturnValue' has a wrong offset!");

}

