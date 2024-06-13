#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialRearmWidget

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "InputCore_structs.hpp"
#include "UMG_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function RadialRearmWidget.RadialRearmWidget_C.ExecuteUbergraph_RadialRearmWidget
// 0x0098 (0x0098 - 0x0000)
struct RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EE7[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialActionModel_C*                K2Node_DynamicCast_AsBP_Radial_Action_Model;       // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EE8[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_ToggleRearmWeapon_C*                K2Node_DynamicCast_AsBP_Toggle_Rearm_Weapon;       // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_CanClick_CanClick;                        // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EE9[0x2];                                     // 0x0032(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Event_UpdatedAngle;                         // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EEA[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_FTrunc_ReturnValue;                       // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_CustomEvent_AmmoRemaining;                  // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EEB[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class URadialCenterRearmButton_C*             K2Node_CustomEvent_CenterWidget;                   // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0058(0x0010)(ZeroConstructor, NoDestructor)
	TDelegate<void(float AmmoRemaining)>          K2Node_CreateDelegate_OutputDelegate_1;            // 0x0068(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EEC[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetMagsToRearmText_ReturnValue;           // 0x0080(0x0018)()
};
static_assert(alignof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget) == 0x000008, "Wrong alignment on RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget");
static_assert(sizeof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget) == 0x000098, "Wrong size on RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, EntryPoint) == 0x000000, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::EntryPoint' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_DynamicCast_AsBP_Radial_Action_Model) == 0x000010, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_DynamicCast_AsBP_Radial_Action_Model' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000020, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_DynamicCast_AsBP_Toggle_Rearm_Weapon) == 0x000028, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_DynamicCast_AsBP_Toggle_Rearm_Weapon' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_DynamicCast_bSuccess_1) == 0x000030, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_CanClick_CanClick) == 0x000031, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_CanClick_CanClick' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_Event_UpdatedAngle) == 0x000034, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_Event_UpdatedAngle' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000038, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_Greater_IntInt_ReturnValue) == 0x00003C, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_FTrunc_ReturnValue) == 0x000040, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_FTrunc_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_CustomEvent_AmmoRemaining) == 0x000044, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_CustomEvent_AmmoRemaining' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_Subtract_IntInt_ReturnValue) == 0x000048, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_CustomEvent_CenterWidget) == 0x000050, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_CustomEvent_CenterWidget' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_CreateDelegate_OutputDelegate) == 0x000058, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, K2Node_CreateDelegate_OutputDelegate_1) == 0x000068, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000078, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget, CallFunc_GetMagsToRearmText_ReturnValue) == 0x000080, "Member 'RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget::CallFunc_GetMagsToRearmText_ReturnValue' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.SetCenterWidget
// 0x0008 (0x0008 - 0x0000)
struct RadialRearmWidget_C_SetCenterWidget final
{
public:
	class URadialCenterRearmButton_C*             Param_CenterWidget;                                // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialRearmWidget_C_SetCenterWidget) == 0x000008, "Wrong alignment on RadialRearmWidget_C_SetCenterWidget");
static_assert(sizeof(RadialRearmWidget_C_SetCenterWidget) == 0x000008, "Wrong size on RadialRearmWidget_C_SetCenterWidget");
static_assert(offsetof(RadialRearmWidget_C_SetCenterWidget, Param_CenterWidget) == 0x000000, "Member 'RadialRearmWidget_C_SetCenterWidget::Param_CenterWidget' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.AmmoRemainingUpdated
// 0x0004 (0x0004 - 0x0000)
struct RadialRearmWidget_C_AmmoRemainingUpdated final
{
public:
	float                                         AmmoRemaining;                                     // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialRearmWidget_C_AmmoRemainingUpdated) == 0x000004, "Wrong alignment on RadialRearmWidget_C_AmmoRemainingUpdated");
static_assert(sizeof(RadialRearmWidget_C_AmmoRemainingUpdated) == 0x000004, "Wrong size on RadialRearmWidget_C_AmmoRemainingUpdated");
static_assert(offsetof(RadialRearmWidget_C_AmmoRemainingUpdated, AmmoRemaining) == 0x000000, "Member 'RadialRearmWidget_C_AmmoRemainingUpdated::AmmoRemaining' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.UpdateRadialAngle
// 0x0004 (0x0004 - 0x0000)
struct RadialRearmWidget_C_UpdateRadialAngle final
{
public:
	float                                         UpdatedAngle;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialRearmWidget_C_UpdateRadialAngle) == 0x000004, "Wrong alignment on RadialRearmWidget_C_UpdateRadialAngle");
static_assert(sizeof(RadialRearmWidget_C_UpdateRadialAngle) == 0x000004, "Wrong size on RadialRearmWidget_C_UpdateRadialAngle");
static_assert(offsetof(RadialRearmWidget_C_UpdateRadialAngle, UpdatedAngle) == 0x000000, "Member 'RadialRearmWidget_C_UpdateRadialAngle::UpdatedAngle' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.GetMagsToRearmText
// 0x00E0 (0x00E0 - 0x0000)
struct RadialRearmWidget_C_GetMagsToRearmText final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
	int32                                         CurrentItems;                                      // 0x0018(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         MaxItems;                                          // 0x001C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetRearmItemCount_ReturnValue;            // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetRearmMaxItemCount_ReturnValue;         // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_IntInt_ReturnValue;          // 0x002C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EED[0x3];                                     // 0x002D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EEE[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0038(0x0040)(HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0078(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x00B8(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00C8(0x0018)()
};
static_assert(alignof(RadialRearmWidget_C_GetMagsToRearmText) == 0x000008, "Wrong alignment on RadialRearmWidget_C_GetMagsToRearmText");
static_assert(sizeof(RadialRearmWidget_C_GetMagsToRearmText) == 0x0000E0, "Wrong size on RadialRearmWidget_C_GetMagsToRearmText");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, ReturnValue) == 0x000000, "Member 'RadialRearmWidget_C_GetMagsToRearmText::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CurrentItems) == 0x000018, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CurrentItems' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, MaxItems) == 0x00001C, "Member 'RadialRearmWidget_C_GetMagsToRearmText::MaxItems' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_GetRearmItemCount_ReturnValue) == 0x000020, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_GetRearmItemCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_GetRearmMaxItemCount_ReturnValue) == 0x000024, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_GetRearmMaxItemCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_Add_IntInt_ReturnValue) == 0x000028, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_GreaterEqual_IntInt_ReturnValue) == 0x00002C, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_GreaterEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_Add_IntInt_ReturnValue_1) == 0x000030, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, K2Node_MakeStruct_FormatArgumentData) == 0x000038, "Member 'RadialRearmWidget_C_GetMagsToRearmText::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, K2Node_MakeStruct_FormatArgumentData_1) == 0x000078, "Member 'RadialRearmWidget_C_GetMagsToRearmText::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, K2Node_MakeArray_Array) == 0x0000B8, "Member 'RadialRearmWidget_C_GetMagsToRearmText::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_GetMagsToRearmText, CallFunc_Format_ReturnValue) == 0x0000C8, "Member 'RadialRearmWidget_C_GetMagsToRearmText::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.OnPreviewMouseButtonDown
// 0x03A8 (0x03A8 - 0x0000)
struct RadialRearmWidget_C_OnPreviewMouseButtonDown final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0160(0x00B8)()
	struct FKey                                   CallFunc_PointerEvent_GetEffectingButton_ReturnValue; // 0x0218(0x0018)(HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_KeyKey_ReturnValue;            // 0x0230(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EEF[0x7];                                     // 0x0231(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0238(0x00B8)()
	struct FEventReply                            CallFunc_Handled_ReturnValue_1;                    // 0x02F0(0x00B8)()
};
static_assert(alignof(RadialRearmWidget_C_OnPreviewMouseButtonDown) == 0x000008, "Wrong alignment on RadialRearmWidget_C_OnPreviewMouseButtonDown");
static_assert(sizeof(RadialRearmWidget_C_OnPreviewMouseButtonDown) == 0x0003A8, "Wrong size on RadialRearmWidget_C_OnPreviewMouseButtonDown");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, MyGeometry) == 0x000000, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::MyGeometry' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, MouseEvent) == 0x000038, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::MouseEvent' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, ReturnValue) == 0x0000A8, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, CallFunc_Handled_ReturnValue) == 0x000160, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::CallFunc_Handled_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, CallFunc_PointerEvent_GetEffectingButton_ReturnValue) == 0x000218, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::CallFunc_PointerEvent_GetEffectingButton_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, CallFunc_EqualEqual_KeyKey_ReturnValue) == 0x000230, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::CallFunc_EqualEqual_KeyKey_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, CallFunc_Unhandled_ReturnValue) == 0x000238, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::CallFunc_Unhandled_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnPreviewMouseButtonDown, CallFunc_Handled_ReturnValue_1) == 0x0002F0, "Member 'RadialRearmWidget_C_OnPreviewMouseButtonDown::CallFunc_Handled_ReturnValue_1' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.OnMouseButtonDoubleClick
// 0x0238 (0x0238 - 0x0000)
struct RadialRearmWidget_C_OnMouseButtonDoubleClick final
{
public:
	struct FGeometry                              InMyGeometry;                                      // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          InMouseEvent;                                      // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0160(0x00B8)()
	struct FKey                                   CallFunc_PointerEvent_GetEffectingButton_ReturnValue; // 0x0218(0x0018)(HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_KeyKey_ReturnValue;            // 0x0230(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialRearmWidget_C_OnMouseButtonDoubleClick) == 0x000008, "Wrong alignment on RadialRearmWidget_C_OnMouseButtonDoubleClick");
static_assert(sizeof(RadialRearmWidget_C_OnMouseButtonDoubleClick) == 0x000238, "Wrong size on RadialRearmWidget_C_OnMouseButtonDoubleClick");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, InMyGeometry) == 0x000000, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::InMyGeometry' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, InMouseEvent) == 0x000038, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::InMouseEvent' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, ReturnValue) == 0x0000A8, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, CallFunc_Handled_ReturnValue) == 0x000160, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::CallFunc_Handled_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, CallFunc_PointerEvent_GetEffectingButton_ReturnValue) == 0x000218, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::CallFunc_PointerEvent_GetEffectingButton_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_OnMouseButtonDoubleClick, CallFunc_EqualEqual_KeyKey_ReturnValue) == 0x000230, "Member 'RadialRearmWidget_C_OnMouseButtonDoubleClick::CallFunc_EqualEqual_KeyKey_ReturnValue' has a wrong offset!");

// Function RadialRearmWidget.RadialRearmWidget_C.UpdateBackgroundColors
// 0x0002 (0x0002 - 0x0000)
struct RadialRearmWidget_C_UpdateBackgroundColors final
{
public:
	bool                                          CanClick;                                          // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          IsAmmoFull;                                        // 0x0001(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialRearmWidget_C_UpdateBackgroundColors) == 0x000001, "Wrong alignment on RadialRearmWidget_C_UpdateBackgroundColors");
static_assert(sizeof(RadialRearmWidget_C_UpdateBackgroundColors) == 0x000002, "Wrong size on RadialRearmWidget_C_UpdateBackgroundColors");
static_assert(offsetof(RadialRearmWidget_C_UpdateBackgroundColors, CanClick) == 0x000000, "Member 'RadialRearmWidget_C_UpdateBackgroundColors::CanClick' has a wrong offset!");
static_assert(offsetof(RadialRearmWidget_C_UpdateBackgroundColors, IsAmmoFull) == 0x000001, "Member 'RadialRearmWidget_C_UpdateBackgroundColors::IsAmmoFull' has a wrong offset!");

}

