#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Slider_UIScale

#include "Basic.hpp"


namespace SDK::Params
{

// Function W_Slider_UIScale.W_Slider_UIScale_C.ExecuteUbergraph_W_Slider_UIScale
// 0x0098 (0x0098 - 0x0000)
struct W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_46BF[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UPanelWidget*                           CallFunc_GetParent_ReturnValue;                    // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQHUD*                                 K2Node_DynamicCast_AsSQHUD;                        // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46C0[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_ComponentBoundEvent_Value;                  // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_CustomEvent_Value;                          // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_46C1[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0038(0x0018)()
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_MapMarkersEnabledDefined_ReturnValue;     // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46C2[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AGameStateBase*                         CallFunc_GetGameState_ReturnValue;                 // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data_1;          // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQGameState*                           K2Node_DynamicCast_AsSQGame_State;                 // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46C3[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AGameStateBase*                         CallFunc_GetGameState_ReturnValue_1;               // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQGameState*                           K2Node_DynamicCast_AsSQGame_State_1;               // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_MapMarkersEnabledDefined_ReturnValue_1;   // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale) == 0x000008, "Wrong alignment on W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale");
static_assert(sizeof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale) == 0x000098, "Wrong size on W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, EntryPoint) == 0x000000, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_GetParent_ReturnValue) == 0x000008, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_GetParent_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_GetOwningPlayer_ReturnValue) == 0x000010, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_GetHUD_ReturnValue) == 0x000018, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_AsSQHUD) == 0x000020, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_AsSQHUD' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_ComponentBoundEvent_Value) == 0x00002C, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_ComponentBoundEvent_Value' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_CustomEvent_Value) == 0x000030, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_CustomEvent_Value' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_Conv_FloatToText_ReturnValue) == 0x000038, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000050, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_MapMarkersEnabledDefined_ReturnValue) == 0x000058, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_MapMarkersEnabledDefined_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_GetGameState_ReturnValue) == 0x000060, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_GetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_Get_UI_Save_Data_UI_Save_Data_1) == 0x000068, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_Get_UI_Save_Data_UI_Save_Data_1' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_AsSQGame_State) == 0x000070, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_AsSQGame_State' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_bSuccess_1) == 0x000078, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_GetGameState_ReturnValue_1) == 0x000080, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_GetGameState_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_AsSQGame_State_1) == 0x000088, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_AsSQGame_State_1' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, K2Node_DynamicCast_bSuccess_2) == 0x000090, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale, CallFunc_MapMarkersEnabledDefined_ReturnValue_1) == 0x000091, "Member 'W_Slider_UIScale_C_ExecuteUbergraph_W_Slider_UIScale::CallFunc_MapMarkersEnabledDefined_ReturnValue_1' has a wrong offset!");

// Function W_Slider_UIScale.W_Slider_UIScale_C.Set Value
// 0x0004 (0x0004 - 0x0000)
struct W_Slider_UIScale_C_Set_Value final
{
public:
	float                                         Value;                                             // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Slider_UIScale_C_Set_Value) == 0x000004, "Wrong alignment on W_Slider_UIScale_C_Set_Value");
static_assert(sizeof(W_Slider_UIScale_C_Set_Value) == 0x000004, "Wrong size on W_Slider_UIScale_C_Set_Value");
static_assert(offsetof(W_Slider_UIScale_C_Set_Value, Value) == 0x000000, "Member 'W_Slider_UIScale_C_Set_Value::Value' has a wrong offset!");

// Function W_Slider_UIScale.W_Slider_UIScale_C.BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature
// 0x0004 (0x0004 - 0x0000)
struct W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature final
{
public:
	float                                         Value;                                             // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature) == 0x000004, "Wrong alignment on W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature");
static_assert(sizeof(W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature) == 0x000004, "Wrong size on W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature");
static_assert(offsetof(W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature, Value) == 0x000000, "Member 'W_Slider_UIScale_C_BndEvt__SettingsItem_Slider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature::Value' has a wrong offset!");

}

