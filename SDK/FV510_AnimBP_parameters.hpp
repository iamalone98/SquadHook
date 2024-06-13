#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FV510_AnimBP

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function FV510_AnimBP.FV510_AnimBP_C.ExecuteUbergraph_FV510_AnimBP
// 0x0004 (0x0004 - 0x0000)
struct FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP) == 0x000004, "Wrong alignment on FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP");
static_assert(sizeof(FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP) == 0x000004, "Wrong size on FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP");
static_assert(offsetof(FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP, EntryPoint) == 0x000000, "Member 'FV510_AnimBP_C_ExecuteUbergraph_FV510_AnimBP::EntryPoint' has a wrong offset!");

// Function FV510_AnimBP.FV510_AnimBP_C.AnimGraph
// 0x0010 (0x0010 - 0x0000)
struct FV510_AnimBP_C_AnimGraph final
{
public:
	struct FPoseLink                              Param_AnimGraph;                                   // 0x0000(0x0010)(Parm, OutParm, NoDestructor)
};
static_assert(alignof(FV510_AnimBP_C_AnimGraph) == 0x000008, "Wrong alignment on FV510_AnimBP_C_AnimGraph");
static_assert(sizeof(FV510_AnimBP_C_AnimGraph) == 0x000010, "Wrong size on FV510_AnimBP_C_AnimGraph");
static_assert(offsetof(FV510_AnimBP_C_AnimGraph, Param_AnimGraph) == 0x000000, "Member 'FV510_AnimBP_C_AnimGraph::Param_AnimGraph' has a wrong offset!");

}

