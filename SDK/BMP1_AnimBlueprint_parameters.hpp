#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BMP1_AnimBlueprint

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BMP1_AnimBlueprint.BMP1_AnimBlueprint_C.ExecuteUbergraph_BMP1_AnimBlueprint
// 0x0004 (0x0004 - 0x0000)
struct BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint) == 0x000004, "Wrong alignment on BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint");
static_assert(sizeof(BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint) == 0x000004, "Wrong size on BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint");
static_assert(offsetof(BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint, EntryPoint) == 0x000000, "Member 'BMP1_AnimBlueprint_C_ExecuteUbergraph_BMP1_AnimBlueprint::EntryPoint' has a wrong offset!");

// Function BMP1_AnimBlueprint.BMP1_AnimBlueprint_C.AnimGraph
// 0x0010 (0x0010 - 0x0000)
struct BMP1_AnimBlueprint_C_AnimGraph final
{
public:
	struct FPoseLink                              Param_AnimGraph;                                   // 0x0000(0x0010)(Parm, OutParm, NoDestructor)
};
static_assert(alignof(BMP1_AnimBlueprint_C_AnimGraph) == 0x000008, "Wrong alignment on BMP1_AnimBlueprint_C_AnimGraph");
static_assert(sizeof(BMP1_AnimBlueprint_C_AnimGraph) == 0x000010, "Wrong size on BMP1_AnimBlueprint_C_AnimGraph");
static_assert(offsetof(BMP1_AnimBlueprint_C_AnimGraph, Param_AnimGraph) == 0x000000, "Member 'BMP1_AnimBlueprint_C_AnimGraph::Param_AnimGraph' has a wrong offset!");

}

