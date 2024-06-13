#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_FOB

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "S_FOBRadius_structs.hpp"


namespace SDK::Params
{

// Function BP_MapMarker_FOB.BP_MapMarker_FOB_C.ExecuteUbergraph_BP_MapMarker_FOB
// 0x0110 (0x0110 - 0x0000)
struct BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Event_ScaleValue;                           // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AGameStateBase*                         CallFunc_GetGameState_ReturnValue;                 // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetServerWorldTimeSeconds_ReturnValue;    // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x001C(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_21D8[0x4];                                     // 0x002C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NearlyEqual_FloatFloat_ReturnValue;       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21D9[0x6];                                     // 0x003A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0048(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21DA[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_HUD_C*                              K2Node_DynamicCast_AsBP_HUD;                       // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21DB[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SQMapCore_C*                         CallFunc_Get_Map_Core_Map_Core;                    // 0x0070(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandUI_C*                         K2Node_DynamicCast_AsW_Command_UI;                 // 0x0078(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21DC[0x7];                                     // 0x0081(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_DeploymentMenu_C*                    K2Node_DynamicCast_AsW_Deployment_Menu;            // 0x0088(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21DD[0x3];                                     // 0x0091(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0094(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_2;            // 0x00A4(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_3;            // 0x00B4(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_21DE[0x4];                                     // 0x00C4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21DF[0x7];                                     // 0x00D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x00D8(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x00F8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21E0[0x3];                                     // 0x00F9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_IntFloat_ReturnValue;            // 0x00FC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_IntFloat_ReturnValue_1;          // 0x0100(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_21E1[0x4];                                     // 0x0104(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB) == 0x000008, "Wrong alignment on BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB");
static_assert(sizeof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB) == 0x000110, "Wrong size on BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, EntryPoint) == 0x000000, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_Event_ScaleValue) == 0x000004, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_Event_ScaleValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetGameState_ReturnValue) == 0x000010, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetServerWorldTimeSeconds_ReturnValue) == 0x000018, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetServerWorldTimeSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_CreateDelegate_OutputDelegate) == 0x00001C, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetOwningPlayer_ReturnValue) == 0x000030, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_NearlyEqual_FloatFloat_ReturnValue) == 0x000038, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_NearlyEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_IsValid_ReturnValue) == 0x000039, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetHUD_ReturnValue) == 0x000040, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_AsBPI_HUD) == 0x000048, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_bSuccess) == 0x000058, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_AsBP_HUD) == 0x000060, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_AsBP_HUD' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_bSuccess_1) == 0x000068, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_Get_Map_Core_Map_Core) == 0x000070, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_Get_Map_Core_Map_Core' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_AsW_Command_UI) == 0x000078, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_AsW_Command_UI' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_bSuccess_2) == 0x000080, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_AsW_Deployment_Menu) == 0x000088, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_AsW_Deployment_Menu' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_DynamicCast_bSuccess_3) == 0x000090, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_CreateDelegate_OutputDelegate_1) == 0x000094, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_CreateDelegate_OutputDelegate_2) == 0x0000A4, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_CreateDelegate_OutputDelegate_2' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, K2Node_CreateDelegate_OutputDelegate_3) == 0x0000B4, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::K2Node_CreateDelegate_OutputDelegate_3' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_TryGetCurrentLayer_OutLayer) == 0x0000C8, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x0000D0, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetDataTableRowFromName_OutRow) == 0x0000D8, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x0000F8, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_Multiply_IntFloat_ReturnValue) == 0x0000FC, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_Multiply_IntFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_Multiply_IntFloat_ReturnValue_1) == 0x000100, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_Multiply_IntFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000108, "Member 'BP_MapMarker_FOB_C_ExecuteUbergraph_BP_MapMarker_FOB::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");

// Function BP_MapMarker_FOB.BP_MapMarker_FOB_C.OnScaleChanged
// 0x0004 (0x0004 - 0x0000)
struct BP_MapMarker_FOB_C_OnScaleChanged final
{
public:
	float                                         ScaleValue;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapMarker_FOB_C_OnScaleChanged) == 0x000004, "Wrong alignment on BP_MapMarker_FOB_C_OnScaleChanged");
static_assert(sizeof(BP_MapMarker_FOB_C_OnScaleChanged) == 0x000004, "Wrong size on BP_MapMarker_FOB_C_OnScaleChanged");
static_assert(offsetof(BP_MapMarker_FOB_C_OnScaleChanged, ScaleValue) == 0x000000, "Member 'BP_MapMarker_FOB_C_OnScaleChanged::ScaleValue' has a wrong offset!");

// Function BP_MapMarker_FOB.BP_MapMarker_FOB_C.Update Radius Visibility
// 0x0018 (0x0018 - 0x0000)
struct BP_MapMarker_FOB_C_Update_Radius_Visibility final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_21E2[0x5];                                     // 0x0003(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapMarker_FOB_C_Update_Radius_Visibility) == 0x000008, "Wrong alignment on BP_MapMarker_FOB_C_Update_Radius_Visibility");
static_assert(sizeof(BP_MapMarker_FOB_C_Update_Radius_Visibility) == 0x000018, "Wrong size on BP_MapMarker_FOB_C_Update_Radius_Visibility");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Radius_Visibility, Temp_bool_Variable) == 0x000000, "Member 'BP_MapMarker_FOB_C_Update_Radius_Visibility::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Radius_Visibility, Temp_byte_Variable) == 0x000001, "Member 'BP_MapMarker_FOB_C_Update_Radius_Visibility::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Radius_Visibility, Temp_byte_Variable_1) == 0x000002, "Member 'BP_MapMarker_FOB_C_Update_Radius_Visibility::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Radius_Visibility, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000008, "Member 'BP_MapMarker_FOB_C_Update_Radius_Visibility::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Radius_Visibility, K2Node_Select_Default) == 0x000010, "Member 'BP_MapMarker_FOB_C_Update_Radius_Visibility::K2Node_Select_Default' has a wrong offset!");

// Function BP_MapMarker_FOB.BP_MapMarker_FOB_C.Update Size
// 0x003C (0x003C - 0x0000)
struct BP_MapMarker_FOB_C_Update_Size final
{
public:
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_21E3[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FMargin                                CallFunc_GetOffsets_ReturnValue;                   // 0x0008(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1; // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_GetDesiredSize_ReturnValue;               // 0x001C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X;                          // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FMargin                                K2Node_MakeStruct_Margin;                          // 0x002C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_MapMarker_FOB_C_Update_Size) == 0x000004, "Wrong alignment on BP_MapMarker_FOB_C_Update_Size");
static_assert(sizeof(BP_MapMarker_FOB_C_Update_Size) == 0x00003C, "Wrong size on BP_MapMarker_FOB_C_Update_Size");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_IsValid_ReturnValue) == 0x000000, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x000004, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_GetOffsets_ReturnValue) == 0x000008, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_GetOffsets_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1) == 0x000018, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_GetDesiredSize_ReturnValue) == 0x00001C, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_GetDesiredSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_BreakVector2D_X) == 0x000024, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, CallFunc_BreakVector2D_Y) == 0x000028, "Member 'BP_MapMarker_FOB_C_Update_Size::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(BP_MapMarker_FOB_C_Update_Size, K2Node_MakeStruct_Margin) == 0x00002C, "Member 'BP_MapMarker_FOB_C_Update_Size::K2Node_MakeStruct_Margin' has a wrong offset!");

}
