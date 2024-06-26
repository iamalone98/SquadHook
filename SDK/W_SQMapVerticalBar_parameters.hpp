#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQMapVerticalBar

#include "Basic.hpp"

#include "UMG_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_SQMapVerticalBar.W_SQMapVerticalBar_C.ExecuteUbergraph_W_SQMapVerticalBar
// 0x0008 (0x0008 - 0x0000)
struct W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar) == 0x000004, "Wrong alignment on W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar");
static_assert(sizeof(W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar) == 0x000008, "Wrong size on W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar");
static_assert(offsetof(W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar, EntryPoint) == 0x000000, "Member 'W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar, K2Node_Event_IsDesignTime) == 0x000004, "Member 'W_SQMapVerticalBar_C_ExecuteUbergraph_W_SQMapVerticalBar::K2Node_Event_IsDesignTime' has a wrong offset!");

// Function W_SQMapVerticalBar.W_SQMapVerticalBar_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct W_SQMapVerticalBar_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_SQMapVerticalBar_C_PreConstruct) == 0x000001, "Wrong alignment on W_SQMapVerticalBar_C_PreConstruct");
static_assert(sizeof(W_SQMapVerticalBar_C_PreConstruct) == 0x000001, "Wrong size on W_SQMapVerticalBar_C_PreConstruct");
static_assert(offsetof(W_SQMapVerticalBar_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'W_SQMapVerticalBar_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function W_SQMapVerticalBar.W_SQMapVerticalBar_C.Configure
// 0x00F0 (0x00F0 - 0x0000)
struct W_SQMapVerticalBar_C_Configure final
{
public:
	float                                         Param_GridLines;                                   // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4559[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0010(0x0018)()
	class FString                                 CallFunc_ConvertNumberToGridLetter_OutResult;      // 0x0028(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_455A[0x4];                                     // 0x003C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0040(0x0018)()
	bool                                          Temp_bool_Variable;                                // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_455B[0x3];                                     // 0x0059(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSlateChildSize                        K2Node_MakeStruct_SlateChildSize;                  // 0x005C(0x0008)(NoDestructor)
	uint8                                         Pad_455C[0x4];                                     // 0x0064(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USizeBoxSlot*                           K2Node_DynamicCast_AsSize_Box_Slot;                // 0x0068(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_455D[0x3];                                     // 0x0071(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_FCeil_ReturnValue;                        // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   K2Node_Select_Default;                             // 0x0078(0x0018)()
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x009C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NearlyEqual_FloatFloat_ReturnValue;       // 0x009D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_455E[0x2];                                     // 0x009E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FMargin                                K2Node_MakeStruct_Margin;                          // 0x00AC(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_455F[0x4];                                     // 0x00BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_VerticalMarker_C*                    CallFunc_Create_ReturnValue;                       // 0x00C8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FMargin                                K2Node_MakeStruct_Margin_1;                        // 0x00D0(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	class UVerticalBoxSlot*                       CallFunc_SlotAsVerticalBoxSlot_ReturnValue;        // 0x00E0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue;                     // 0x00E8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SQMapVerticalBar_C_Configure) == 0x000008, "Wrong alignment on W_SQMapVerticalBar_C_Configure");
static_assert(sizeof(W_SQMapVerticalBar_C_Configure) == 0x0000F0, "Wrong size on W_SQMapVerticalBar_C_Configure");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, Param_GridLines) == 0x000000, "Member 'W_SQMapVerticalBar_C_Configure::Param_GridLines' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, Temp_int_Variable) == 0x000004, "Member 'W_SQMapVerticalBar_C_Configure::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Conv_IntToText_ReturnValue) == 0x000010, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_ConvertNumberToGridLetter_OutResult) == 0x000028, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_ConvertNumberToGridLetter_OutResult' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Add_IntInt_ReturnValue_1) == 0x000038, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Conv_StringToText_ReturnValue) == 0x000040, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, Temp_bool_Variable) == 0x000058, "Member 'W_SQMapVerticalBar_C_Configure::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_MakeStruct_SlateChildSize) == 0x00005C, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_MakeStruct_SlateChildSize' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_DynamicCast_AsSize_Box_Slot) == 0x000068, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_DynamicCast_AsSize_Box_Slot' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_DynamicCast_bSuccess) == 0x000070, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_FCeil_ReturnValue) == 0x000074, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_FCeil_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_Select_Default) == 0x000078, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Conv_IntToFloat_ReturnValue) == 0x000090, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Subtract_IntInt_ReturnValue) == 0x000094, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000098, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_LessEqual_IntInt_ReturnValue) == 0x00009C, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_NearlyEqual_FloatFloat_ReturnValue) == 0x00009D, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_NearlyEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000A0, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x0000A4, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0000A8, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_MakeStruct_Margin) == 0x0000AC, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_MakeStruct_Margin' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_GetOwningPlayer_ReturnValue) == 0x0000C0, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_Create_ReturnValue) == 0x0000C8, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, K2Node_MakeStruct_Margin_1) == 0x0000D0, "Member 'W_SQMapVerticalBar_C_Configure::K2Node_MakeStruct_Margin_1' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_SlotAsVerticalBoxSlot_ReturnValue) == 0x0000E0, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_SlotAsVerticalBoxSlot_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQMapVerticalBar_C_Configure, CallFunc_AddChild_ReturnValue) == 0x0000E8, "Member 'W_SQMapVerticalBar_C_Configure::CallFunc_AddChild_ReturnValue' has a wrong offset!");

}

