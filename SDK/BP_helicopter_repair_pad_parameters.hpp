#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_helicopter_repair_pad

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BP_helicopter_repair_pad.BP_helicopter_repair_pad_C.ExecuteUbergraph_BP_helicopter_repair_pad
// 0x0020 (0x0020 - 0x0000)
struct BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AC4[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void(ESQBuildState BuildState)>     K2Node_CreateDelegate_OutputDelegate;              // 0x0008(0x0010)(ZeroConstructor, NoDestructor)
	int32                                         K2Node_Event_team;                                 // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQBuildState                                 K2Node_CustomEvent_BuildState;                     // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad) == 0x000004, "Wrong alignment on BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad");
static_assert(sizeof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad) == 0x000020, "Wrong size on BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad");
static_assert(offsetof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad, EntryPoint) == 0x000000, "Member 'BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad, K2Node_CreateDelegate_OutputDelegate) == 0x000008, "Member 'BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad, K2Node_Event_team) == 0x000018, "Member 'BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad::K2Node_Event_team' has a wrong offset!");
static_assert(offsetof(BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad, K2Node_CustomEvent_BuildState) == 0x00001C, "Member 'BP_helicopter_repair_pad_C_ExecuteUbergraph_BP_helicopter_repair_pad::K2Node_CustomEvent_BuildState' has a wrong offset!");

// Function BP_helicopter_repair_pad.BP_helicopter_repair_pad_C.OnBuildStateChange_Event
// 0x0001 (0x0001 - 0x0000)
struct BP_helicopter_repair_pad_C_OnBuildStateChange_Event final
{
public:
	ESQBuildState                                 Param_BuildState;                                  // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_helicopter_repair_pad_C_OnBuildStateChange_Event) == 0x000001, "Wrong alignment on BP_helicopter_repair_pad_C_OnBuildStateChange_Event");
static_assert(sizeof(BP_helicopter_repair_pad_C_OnBuildStateChange_Event) == 0x000001, "Wrong size on BP_helicopter_repair_pad_C_OnBuildStateChange_Event");
static_assert(offsetof(BP_helicopter_repair_pad_C_OnBuildStateChange_Event, Param_BuildState) == 0x000000, "Member 'BP_helicopter_repair_pad_C_OnBuildStateChange_Event::Param_BuildState' has a wrong offset!");

// Function BP_helicopter_repair_pad.BP_helicopter_repair_pad_C.SetTeam
// 0x0004 (0x0004 - 0x0000)
struct BP_helicopter_repair_pad_C_SetTeam final
{
public:
	int32                                         Param_Team;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_helicopter_repair_pad_C_SetTeam) == 0x000004, "Wrong alignment on BP_helicopter_repair_pad_C_SetTeam");
static_assert(sizeof(BP_helicopter_repair_pad_C_SetTeam) == 0x000004, "Wrong size on BP_helicopter_repair_pad_C_SetTeam");
static_assert(offsetof(BP_helicopter_repair_pad_C_SetTeam, Param_Team) == 0x000000, "Member 'BP_helicopter_repair_pad_C_SetTeam::Param_Team' has a wrong offset!");

}
