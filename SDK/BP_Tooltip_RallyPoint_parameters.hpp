#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Tooltip_RallyPoint

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_Tooltip_RallyPoint.BP_Tooltip_RallyPoint_C.ExecuteUbergraph_BP_Tooltip_RallyPoint
// 0x0010 (0x0010 - 0x0000)
struct BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_30B3[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint) == 0x000008, "Wrong alignment on BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint");
static_assert(sizeof(BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint) == 0x000010, "Wrong size on BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint, EntryPoint) == 0x000000, "Member 'BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'BP_Tooltip_RallyPoint_C_ExecuteUbergraph_BP_Tooltip_RallyPoint::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");

// Function BP_Tooltip_RallyPoint.BP_Tooltip_RallyPoint_C.GetText_0
// 0x00B8 (0x00B8 - 0x0000)
struct BP_Tooltip_RallyPoint_C_GetText_0 final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
	class FText                                   Spawnsleft_text;                                   // 0x0018(0x0018)(Edit, BlueprintVisible)
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30B4[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_SquadRallyPoint_C*                  K2Node_DynamicCast_AsBP_Squad_Rally_Point;         // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30B5[0x3];                                     // 0x0049(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetNumberOfSpawns_ReturnValue;            // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0050(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0090(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00A0(0x0018)()
};
static_assert(alignof(BP_Tooltip_RallyPoint_C_GetText_0) == 0x000008, "Wrong alignment on BP_Tooltip_RallyPoint_C_GetText_0");
static_assert(sizeof(BP_Tooltip_RallyPoint_C_GetText_0) == 0x0000B8, "Wrong size on BP_Tooltip_RallyPoint_C_GetText_0");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, ReturnValue) == 0x000000, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, Spawnsleft_text) == 0x000018, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::Spawnsleft_text' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, CallFunc_GetOwner_ReturnValue) == 0x000030, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, CallFunc_IsValid_ReturnValue) == 0x000038, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, K2Node_DynamicCast_AsBP_Squad_Rally_Point) == 0x000040, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::K2Node_DynamicCast_AsBP_Squad_Rally_Point' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, CallFunc_GetNumberOfSpawns_ReturnValue) == 0x00004C, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::CallFunc_GetNumberOfSpawns_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, K2Node_MakeStruct_FormatArgumentData) == 0x000050, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, K2Node_MakeArray_Array) == 0x000090, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(BP_Tooltip_RallyPoint_C_GetText_0, CallFunc_Format_ReturnValue) == 0x0000A0, "Member 'BP_Tooltip_RallyPoint_C_GetText_0::CallFunc_Format_ReturnValue' has a wrong offset!");

}
