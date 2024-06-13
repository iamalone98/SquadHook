#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_CO_Orderline

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function BP_MapMarker_CO_Orderline.BP_MapMarker_CO_Orderline_C.ExecuteUbergraph_BP_MapMarker_CO_Orderline
// 0x0120 (0x0120 - 0x0000)
struct BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_466F[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AGameStateBase*                         CallFunc_GetGameState_ReturnValue;                 // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetServerWorldTimeSeconds_ReturnValue;    // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4670[0x4];                                     // 0x002C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NearlyEqual_FloatFloat_ReturnValue;       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4671[0x6];                                     // 0x003A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0048(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4672[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_HUD_C*                              K2Node_DynamicCast_AsBP_HUD;                       // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4673[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SQMapCore_C*                         CallFunc_Get_Map_Core_Map_Core;                    // 0x0070(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandUI_C*                         K2Node_DynamicCast_AsW_Command_UI;                 // 0x0078(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4674[0x7];                                     // 0x0081(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_DeploymentMenu_C*                    K2Node_DynamicCast_AsW_Deployment_Menu;            // 0x0088(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4675[0x3];                                     // 0x0091(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0094(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_2;            // 0x00A4(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_4676[0x4];                                     // 0x00B4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSlateColor                            K2Node_MakeStruct_SlateColor;                      // 0x00B8(0x0028)()
	float                                         CallFunc_BreakVector_X;                            // 0x00E0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x00E4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x00E8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x00EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4677[0x4];                                     // 0x00F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x00F8(0x0018)()
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_3;            // 0x0110(0x0010)(ZeroConstructor, NoDestructor)
};
static_assert(alignof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline) == 0x000008, "Wrong alignment on BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline");
static_assert(sizeof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline) == 0x000120, "Wrong size on BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, EntryPoint) == 0x000000, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_PlayAnimation_ReturnValue) == 0x000018, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_GetGameState_ReturnValue) == 0x000020, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_GetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_GetServerWorldTimeSeconds_ReturnValue) == 0x000028, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_GetServerWorldTimeSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_GetOwningPlayer_ReturnValue) == 0x000030, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_NearlyEqual_FloatFloat_ReturnValue) == 0x000038, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_NearlyEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_IsValid_ReturnValue) == 0x000039, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_GetHUD_ReturnValue) == 0x000040, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_AsBPI_HUD) == 0x000048, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_bSuccess) == 0x000058, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_AsBP_HUD) == 0x000060, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_AsBP_HUD' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_bSuccess_1) == 0x000068, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_Get_Map_Core_Map_Core) == 0x000070, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_Get_Map_Core_Map_Core' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_AsW_Command_UI) == 0x000078, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_AsW_Command_UI' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_bSuccess_2) == 0x000080, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_AsW_Deployment_Menu) == 0x000088, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_AsW_Deployment_Menu' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_DynamicCast_bSuccess_3) == 0x000090, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_CreateDelegate_OutputDelegate_1) == 0x000094, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_CreateDelegate_OutputDelegate_2) == 0x0000A4, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_CreateDelegate_OutputDelegate_2' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_MakeStruct_SlateColor) == 0x0000B8, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_MakeStruct_SlateColor' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_BreakVector_X) == 0x0000E0, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_BreakVector_Y) == 0x0000E4, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_BreakVector_Z) == 0x0000E8, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0000EC, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_Add_FloatFloat_ReturnValue) == 0x0000F0, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, CallFunc_Conv_IntToText_ReturnValue) == 0x0000F8, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline, K2Node_CreateDelegate_OutputDelegate_3) == 0x000110, "Member 'BP_MapMarker_CO_Orderline_C_ExecuteUbergraph_BP_MapMarker_CO_Orderline::K2Node_CreateDelegate_OutputDelegate_3' has a wrong offset!");

// Function BP_MapMarker_CO_Orderline.BP_MapMarker_CO_Orderline_C.RefreshVisibility
// 0x0018 (0x0018 - 0x0000)
struct BP_MapMarker_CO_Orderline_C_RefreshVisibility final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4678[0x5];                                     // 0x0003(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapMarker_CO_Orderline_C_RefreshVisibility) == 0x000008, "Wrong alignment on BP_MapMarker_CO_Orderline_C_RefreshVisibility");
static_assert(sizeof(BP_MapMarker_CO_Orderline_C_RefreshVisibility) == 0x000018, "Wrong size on BP_MapMarker_CO_Orderline_C_RefreshVisibility");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_RefreshVisibility, Temp_bool_Variable) == 0x000000, "Member 'BP_MapMarker_CO_Orderline_C_RefreshVisibility::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_RefreshVisibility, Temp_byte_Variable) == 0x000001, "Member 'BP_MapMarker_CO_Orderline_C_RefreshVisibility::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_RefreshVisibility, Temp_byte_Variable_1) == 0x000002, "Member 'BP_MapMarker_CO_Orderline_C_RefreshVisibility::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_RefreshVisibility, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000008, "Member 'BP_MapMarker_CO_Orderline_C_RefreshVisibility::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_RefreshVisibility, K2Node_Select_Default) == 0x000010, "Member 'BP_MapMarker_CO_Orderline_C_RefreshVisibility::K2Node_Select_Default' has a wrong offset!");

// Function BP_MapMarker_CO_Orderline.BP_MapMarker_CO_Orderline_C.InitDirectorMarker
// 0x0110 (0x0110 - 0x0000)
struct BP_MapMarker_CO_Orderline_C_InitDirectorMarker final
{
public:
	struct FSQMapMarkerVisualData                 CallFunc_GetMapMarkerData_ReturnValue;             // 0x0000(0x00C8)(NoDestructor)
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x00C8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x00D4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_RotatorFromAxisAndAngle_ReturnValue;      // 0x00E0(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector                                CallFunc_Conv_Vector2DToVector_ReturnValue;        // 0x00EC(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GreaterGreater_VectorRotator_ReturnValue; // 0x00F8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Conv_VectorToVector2D_ReturnValue;        // 0x0104(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker) == 0x000008, "Wrong alignment on BP_MapMarker_CO_Orderline_C_InitDirectorMarker");
static_assert(sizeof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker) == 0x000110, "Wrong size on BP_MapMarker_CO_Orderline_C_InitDirectorMarker");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_GetMapMarkerData_ReturnValue) == 0x000000, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_GetMapMarkerData_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x0000C8, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Add_FloatFloat_ReturnValue) == 0x0000CC, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000D0, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x0000D4, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_MakeVector2D_ReturnValue) == 0x0000D8, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_RotatorFromAxisAndAngle_ReturnValue) == 0x0000E0, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_RotatorFromAxisAndAngle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Conv_Vector2DToVector_ReturnValue) == 0x0000EC, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Conv_Vector2DToVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_GreaterGreater_VectorRotator_ReturnValue) == 0x0000F8, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_GreaterGreater_VectorRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_CO_Orderline_C_InitDirectorMarker, CallFunc_Conv_VectorToVector2D_ReturnValue) == 0x000104, "Member 'BP_MapMarker_CO_Orderline_C_InitDirectorMarker::CallFunc_Conv_VectorToVector2D_ReturnValue' has a wrong offset!");

}

