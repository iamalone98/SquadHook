#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetForwardBase

#include "Basic.hpp"

#include "UMG_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "S_FOBRadius_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.ExecuteUbergraph_BP_MapWidgetForwardBase
// 0x0118 (0x0118 - 0x0000)
struct BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQColorsDataAsset*                     CallFunc_Get_SQHUD_Colors_ColorsDataAsset;         // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_GetColor_ReturnValue;                     // 0x0048(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0058(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0068(0x0018)()
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue_1;           // 0x0080(0x0018)()
	float                                         K2Node_Event_UniformScale;                         // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4745[0x4];                                     // 0x009C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4746[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_HUD_C*                              K2Node_DynamicCast_AsBP_HUD;                       // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4747[0x3];                                     // 0x00C1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x00C4(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_4748[0x4];                                     // 0x00D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_CommandUI_C*                         K2Node_DynamicCast_AsW_Command_UI;                 // 0x00D8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x00E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4749[0x7];                                     // 0x00E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_DeploymentMenu_C*                    K2Node_DynamicCast_AsW_Deployment_Menu;            // 0x00E8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_474A[0x3];                                     // 0x00F1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x00F4(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0104(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_474B[0x3];                                     // 0x0105(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data_1;          // 0x0110(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase");
static_assert(sizeof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase) == 0x000118, "Wrong size on BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, EntryPoint) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_Event_MyGeometry) == 0x000004, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_Get_SQHUD_Colors_ColorsDataAsset) == 0x000040, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_Get_SQHUD_Colors_ColorsDataAsset' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_GetColor_ReturnValue) == 0x000048, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_GetColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_SelectColor_ReturnValue) == 0x000058, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_SelectColor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_Conv_FloatToText_ReturnValue) == 0x000068, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_Conv_FloatToText_ReturnValue_1) == 0x000080, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_Conv_FloatToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_Event_UniformScale) == 0x000098, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_Event_UniformScale' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_GetOwningPlayer_ReturnValue) == 0x0000A0, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_IsValid_ReturnValue) == 0x0000A8, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_GetHUD_ReturnValue) == 0x0000B0, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_AsBP_HUD) == 0x0000B8, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_AsBP_HUD' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_bSuccess) == 0x0000C0, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_CreateDelegate_OutputDelegate) == 0x0000C4, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_AsW_Command_UI) == 0x0000D8, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_AsW_Command_UI' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_bSuccess_1) == 0x0000E0, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_AsW_Deployment_Menu) == 0x0000E8, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_AsW_Deployment_Menu' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_DynamicCast_bSuccess_2) == 0x0000F0, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, K2Node_CreateDelegate_OutputDelegate_1) == 0x0000F4, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_IsValid_ReturnValue_1) == 0x000104, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000108, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase, CallFunc_Get_UI_Save_Data_UI_Save_Data_1) == 0x000110, "Member 'BP_MapWidgetForwardBase_C_ExecuteUbergraph_BP_MapWidgetForwardBase::CallFunc_Get_UI_Save_Data_UI_Save_Data_1' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.OnScaleChanged
// 0x0004 (0x0004 - 0x0000)
struct BP_MapWidgetForwardBase_C_OnScaleChanged final
{
public:
	float                                         UniformScale;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_OnScaleChanged) == 0x000004, "Wrong alignment on BP_MapWidgetForwardBase_C_OnScaleChanged");
static_assert(sizeof(BP_MapWidgetForwardBase_C_OnScaleChanged) == 0x000004, "Wrong size on BP_MapWidgetForwardBase_C_OnScaleChanged");
static_assert(offsetof(BP_MapWidgetForwardBase_C_OnScaleChanged, UniformScale) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_OnScaleChanged::UniformScale' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Tick
// 0x003C (0x003C - 0x0000)
struct BP_MapWidgetForwardBase_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Tick) == 0x000004, "Wrong alignment on BP_MapWidgetForwardBase_C_Tick");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Tick) == 0x00003C, "Wrong size on BP_MapWidgetForwardBase_C_Tick");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Tick, MyGeometry) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Tick, InDeltaTime) == 0x000038, "Member 'BP_MapWidgetForwardBase_C_Tick::InDeltaTime' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Update Construction Radius
// 0x0040 (0x0040 - 0x0000)
struct BP_MapWidgetForwardBase_C_Update_Construction_Radius final
{
public:
	float                                         L_Construction;                                    // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_474C[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x0018(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_474D[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Update_Construction_Radius) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Update_Construction_Radius");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Update_Construction_Radius) == 0x000040, "Wrong size on BP_MapWidgetForwardBase_C_Update_Construction_Radius");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, L_Construction) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::L_Construction' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x000004, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000008, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000010, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_GetDataTableRowFromName_OutRow) == 0x000018, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000038, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Construction_Radius, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00003C, "Member 'BP_MapWidgetForwardBase_C_Update_Construction_Radius::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Update Exclusion Radius
// 0x0040 (0x0040 - 0x0000)
struct BP_MapWidgetForwardBase_C_Update_Exclusion_Radius final
{
public:
	float                                         L_ExclusionDiamater;                               // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_474E[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_474F[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x0018(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4750[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Update_Exclusion_Radius");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius) == 0x000040, "Wrong size on BP_MapWidgetForwardBase_C_Update_Exclusion_Radius");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, L_ExclusionDiamater) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::L_ExclusionDiamater' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000008, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000010, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x000014, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_GetDataTableRowFromName_OutRow) == 0x000018, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000038, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Exclusion_Radius, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00003C, "Member 'BP_MapWidgetForwardBase_C_Update_Exclusion_Radius::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Update Color
// 0x0078 (0x0078 - 0x0000)
struct BP_MapWidgetForwardBase_C_Update_Color final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4751[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           Temp_struct_Variable;                              // 0x0004(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Temp_struct_Variable_1;                            // 0x0014(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_1;                              // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4752[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           Temp_struct_Variable_2;                            // 0x0028(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Temp_struct_Variable_3;                            // 0x0038(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue_1;                // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4753[0x2];                                     // 0x004A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           K2Node_Select_Default;                             // 0x004C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_Select_Default_1;                           // 0x005C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4754[0x4];                                     // 0x006C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Update_Color) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Update_Color");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Update_Color) == 0x000078, "Wrong size on BP_MapWidgetForwardBase_C_Update_Color");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_bool_Variable) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_struct_Variable) == 0x000004, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_struct_Variable_1) == 0x000014, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_bool_Variable_1) == 0x000024, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_struct_Variable_2) == 0x000028, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_struct_Variable_2' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, Temp_struct_Variable_3) == 0x000038, "Member 'BP_MapWidgetForwardBase_C_Update_Color::Temp_struct_Variable_3' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, CallFunc_Not_PreBool_ReturnValue) == 0x000048, "Member 'BP_MapWidgetForwardBase_C_Update_Color::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, CallFunc_Not_PreBool_ReturnValue_1) == 0x000049, "Member 'BP_MapWidgetForwardBase_C_Update_Color::CallFunc_Not_PreBool_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, K2Node_Select_Default) == 0x00004C, "Member 'BP_MapWidgetForwardBase_C_Update_Color::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, K2Node_Select_Default_1) == 0x00005C, "Member 'BP_MapWidgetForwardBase_C_Update_Color::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Color, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000070, "Member 'BP_MapWidgetForwardBase_C_Update_Color::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Update Radius Visibility
// 0x0018 (0x0018 - 0x0000)
struct BP_MapWidgetForwardBase_C_Update_Radius_Visibility final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4755[0x5];                                     // 0x0003(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Update_Radius_Visibility");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility) == 0x000018, "Wrong size on BP_MapWidgetForwardBase_C_Update_Radius_Visibility");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility, Temp_bool_Variable) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Update_Radius_Visibility::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility, Temp_byte_Variable) == 0x000001, "Member 'BP_MapWidgetForwardBase_C_Update_Radius_Visibility::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility, Temp_byte_Variable_1) == 0x000002, "Member 'BP_MapWidgetForwardBase_C_Update_Radius_Visibility::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000008, "Member 'BP_MapWidgetForwardBase_C_Update_Radius_Visibility::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Radius_Visibility, K2Node_Select_Default) == 0x000010, "Member 'BP_MapWidgetForwardBase_C_Update_Radius_Visibility::K2Node_Select_Default' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Update Supplies Visibility
// 0x0018 (0x0018 - 0x0000)
struct BP_MapWidgetForwardBase_C_Update_Supplies_Visibility final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4756[0x5];                                     // 0x0003(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Update_Supplies_Visibility");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility) == 0x000018, "Wrong size on BP_MapWidgetForwardBase_C_Update_Supplies_Visibility");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility, Temp_bool_Variable) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Update_Supplies_Visibility::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility, Temp_byte_Variable) == 0x000001, "Member 'BP_MapWidgetForwardBase_C_Update_Supplies_Visibility::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility, Temp_byte_Variable_1) == 0x000002, "Member 'BP_MapWidgetForwardBase_C_Update_Supplies_Visibility::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000008, "Member 'BP_MapWidgetForwardBase_C_Update_Supplies_Visibility::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Update_Supplies_Visibility, K2Node_Select_Default) == 0x000010, "Member 'BP_MapWidgetForwardBase_C_Update_Supplies_Visibility::K2Node_Select_Default' has a wrong offset!");

// Function BP_MapWidgetForwardBase.BP_MapWidgetForwardBase_C.Get_FOBIcon_ToolTipWidget_0
// 0x0018 (0x0018 - 0x0000)
struct BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0 final
{
public:
	class UWidget*                                ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_Tooltip_FobSupplies_C*               CallFunc_Create_ReturnValue;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0) == 0x000008, "Wrong alignment on BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0");
static_assert(sizeof(BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0) == 0x000018, "Wrong size on BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0, ReturnValue) == 0x000000, "Member 'BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0, CallFunc_Create_ReturnValue) == 0x000010, "Member 'BP_MapWidgetForwardBase_C_Get_FOBIcon_ToolTipWidget_0::CallFunc_Create_ReturnValue' has a wrong offset!");

}

