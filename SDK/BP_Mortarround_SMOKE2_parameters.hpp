#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Mortarround_SMOKE2

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_Mortarround_SMOKE2.BP_Mortarround_SMOKE2_C.ExecuteUbergraph_BP_Mortarround_SMOKE2
// 0x0010 (0x0010 - 0x0000)
struct BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2 final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F9A[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAudioComponent*                        CallFunc_SpawnSoundAttached_ReturnValue;           // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2) == 0x000008, "Wrong alignment on BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2");
static_assert(sizeof(BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2) == 0x000010, "Wrong size on BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2");
static_assert(offsetof(BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2, EntryPoint) == 0x000000, "Member 'BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2, CallFunc_SpawnSoundAttached_ReturnValue) == 0x000008, "Member 'BP_Mortarround_SMOKE2_C_ExecuteUbergraph_BP_Mortarround_SMOKE2::CallFunc_SpawnSoundAttached_ReturnValue' has a wrong offset!");

}

