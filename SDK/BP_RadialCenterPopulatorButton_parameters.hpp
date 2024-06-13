#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialCenterPopulatorButton

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_RadialCenterPopulatorButton.BP_RadialCenterPopulatorButton_C.ExecuteUbergraph_BP_RadialCenterPopulatorButton
// 0x0088 (0x0088 - 0x0000)
struct BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F94[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQUserWidget*                          K2Node_Event_Widget;                               // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_RadialMenu;                           // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  K2Node_Event_ActionModel;                          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          K2Node_Event_Widget_1;                             // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  K2Node_Event_Model;                                // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_RadialMenu_1;                         // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F95[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class ISQRearmSource>        K2Node_DynamicCast_AsSQRearm_Source;               // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0051(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0052(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F96[0x5];                                     // 0x0053(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class URadialCenterRearmButton_C*             K2Node_DynamicCast_AsRadial_Center_Rearm_Button;   // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F97[0x6];                                     // 0x0062(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F98[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class URadialCenterRearmButton_C*             K2Node_DynamicCast_AsRadial_Center_Rearm_Button_1; // 0x0078(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_5;                    // 0x0081(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton) == 0x000008, "Wrong alignment on BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton");
static_assert(sizeof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton) == 0x000088, "Wrong size on BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, EntryPoint) == 0x000000, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_Widget) == 0x000008, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_RadialMenu) == 0x000010, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_RadialMenu' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_ActionModel) == 0x000018, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_ActionModel' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_Widget_1) == 0x000020, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_Widget_1' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_Model) == 0x000028, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_Model' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_Event_RadialMenu_1) == 0x000030, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_Event_RadialMenu_1' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue) == 0x000038, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_AsSQRearm_Source) == 0x000040, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_AsSQRearm_Source' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue_1) == 0x000051, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue_2) == 0x000052, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_AsRadial_Center_Rearm_Button) == 0x000058, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_AsRadial_Center_Rearm_Button' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_bSuccess_1) == 0x000060, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue_3) == 0x000061, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_GetOwningPlayer_ReturnValue) == 0x000068, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue_4) == 0x000070, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_AsRadial_Center_Rearm_Button_1) == 0x000078, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_AsRadial_Center_Rearm_Button_1' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, K2Node_DynamicCast_bSuccess_2) == 0x000080, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton, CallFunc_IsValid_ReturnValue_5) == 0x000081, "Member 'BP_RadialCenterPopulatorButton_C_ExecuteUbergraph_BP_RadialCenterPopulatorButton::CallFunc_IsValid_ReturnValue_5' has a wrong offset!");

// Function BP_RadialCenterPopulatorButton.BP_RadialCenterPopulatorButton_C.FinishWidgetSetup
// 0x0018 (0x0018 - 0x0000)
struct BP_RadialCenterPopulatorButton_C_FinishWidgetSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  ActionModel;                                       // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialCenterPopulatorButton_C_FinishWidgetSetup) == 0x000008, "Wrong alignment on BP_RadialCenterPopulatorButton_C_FinishWidgetSetup");
static_assert(sizeof(BP_RadialCenterPopulatorButton_C_FinishWidgetSetup) == 0x000018, "Wrong size on BP_RadialCenterPopulatorButton_C_FinishWidgetSetup");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_FinishWidgetSetup, Widget) == 0x000000, "Member 'BP_RadialCenterPopulatorButton_C_FinishWidgetSetup::Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_FinishWidgetSetup, RadialMenu) == 0x000008, "Member 'BP_RadialCenterPopulatorButton_C_FinishWidgetSetup::RadialMenu' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_FinishWidgetSetup, ActionModel) == 0x000010, "Member 'BP_RadialCenterPopulatorButton_C_FinishWidgetSetup::ActionModel' has a wrong offset!");

// Function BP_RadialCenterPopulatorButton.BP_RadialCenterPopulatorButton_C.InitialSetup
// 0x0018 (0x0018 - 0x0000)
struct BP_RadialCenterPopulatorButton_C_InitialSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialCenterPopulatorButton_C_InitialSetup) == 0x000008, "Wrong alignment on BP_RadialCenterPopulatorButton_C_InitialSetup");
static_assert(sizeof(BP_RadialCenterPopulatorButton_C_InitialSetup) == 0x000018, "Wrong size on BP_RadialCenterPopulatorButton_C_InitialSetup");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_InitialSetup, Widget) == 0x000000, "Member 'BP_RadialCenterPopulatorButton_C_InitialSetup::Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_InitialSetup, Model) == 0x000008, "Member 'BP_RadialCenterPopulatorButton_C_InitialSetup::Model' has a wrong offset!");
static_assert(offsetof(BP_RadialCenterPopulatorButton_C_InitialSetup, RadialMenu) == 0x000010, "Member 'BP_RadialCenterPopulatorButton_C_InitialSetup::RadialMenu' has a wrong offset!");

}
