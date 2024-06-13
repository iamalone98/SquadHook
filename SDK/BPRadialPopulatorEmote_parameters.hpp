#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPRadialPopulatorEmote

#include "Basic.hpp"


namespace SDK::Params
{

// Function BPRadialPopulatorEmote.BPRadialPopulatorEmote_C.ExecuteUbergraph_BPRadialPopulatorEmote
// 0x0078 (0x0078 - 0x0000)
struct BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F5E[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQUserWidget*                          K2Node_Event_Widget;                               // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_RadialMenu;                           // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  K2Node_Event_ActionModel;                          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          K2Node_Event_Widget_1;                             // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  K2Node_Event_Model;                                // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_RadialMenu_1;                         // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UEmoteRadialEntry_C*                    K2Node_DynamicCast_AsEmote_Radial_Entry;           // 0x0040(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F5F[0x6];                                     // 0x004A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRadialButton*                        K2Node_DynamicCast_AsSQRadial_Button;              // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F60[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQUserWidget*                          K2Node_Event_Widget_2;                             // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_RadialMenu_2;                         // 0x0068(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  K2Node_Event_Model_1;                              // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote) == 0x000008, "Wrong alignment on BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote");
static_assert(sizeof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote) == 0x000078, "Wrong size on BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, EntryPoint) == 0x000000, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::EntryPoint' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_Widget) == 0x000008, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_RadialMenu) == 0x000010, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_ActionModel) == 0x000018, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_ActionModel' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_Widget_1) == 0x000020, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_Widget_1' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_Model) == 0x000028, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_Model' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_RadialMenu_1) == 0x000030, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_RadialMenu_1' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, CallFunc_GetOwningPlayer_ReturnValue) == 0x000038, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_DynamicCast_AsEmote_Radial_Entry) == 0x000040, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_DynamicCast_AsEmote_Radial_Entry' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, CallFunc_IsValid_ReturnValue) == 0x000049, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_DynamicCast_AsSQRadial_Button) == 0x000050, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_DynamicCast_AsSQRadial_Button' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_DynamicCast_bSuccess_1) == 0x000058, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_Widget_2) == 0x000060, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_Widget_2' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_RadialMenu_2) == 0x000068, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_RadialMenu_2' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote, K2Node_Event_Model_1) == 0x000070, "Member 'BPRadialPopulatorEmote_C_ExecuteUbergraph_BPRadialPopulatorEmote::K2Node_Event_Model_1' has a wrong offset!");

// Function BPRadialPopulatorEmote.BPRadialPopulatorEmote_C.FinishWidgetSetup
// 0x0018 (0x0018 - 0x0000)
struct BPRadialPopulatorEmote_C_FinishWidgetSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  ActionModel;                                       // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorEmote_C_FinishWidgetSetup) == 0x000008, "Wrong alignment on BPRadialPopulatorEmote_C_FinishWidgetSetup");
static_assert(sizeof(BPRadialPopulatorEmote_C_FinishWidgetSetup) == 0x000018, "Wrong size on BPRadialPopulatorEmote_C_FinishWidgetSetup");
static_assert(offsetof(BPRadialPopulatorEmote_C_FinishWidgetSetup, Widget) == 0x000000, "Member 'BPRadialPopulatorEmote_C_FinishWidgetSetup::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_FinishWidgetSetup, RadialMenu) == 0x000008, "Member 'BPRadialPopulatorEmote_C_FinishWidgetSetup::RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_FinishWidgetSetup, ActionModel) == 0x000010, "Member 'BPRadialPopulatorEmote_C_FinishWidgetSetup::ActionModel' has a wrong offset!");

// Function BPRadialPopulatorEmote.BPRadialPopulatorEmote_C.InitialSetup
// 0x0018 (0x0018 - 0x0000)
struct BPRadialPopulatorEmote_C_InitialSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorEmote_C_InitialSetup) == 0x000008, "Wrong alignment on BPRadialPopulatorEmote_C_InitialSetup");
static_assert(sizeof(BPRadialPopulatorEmote_C_InitialSetup) == 0x000018, "Wrong size on BPRadialPopulatorEmote_C_InitialSetup");
static_assert(offsetof(BPRadialPopulatorEmote_C_InitialSetup, Widget) == 0x000000, "Member 'BPRadialPopulatorEmote_C_InitialSetup::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_InitialSetup, Model) == 0x000008, "Member 'BPRadialPopulatorEmote_C_InitialSetup::Model' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_InitialSetup, RadialMenu) == 0x000010, "Member 'BPRadialPopulatorEmote_C_InitialSetup::RadialMenu' has a wrong offset!");

// Function BPRadialPopulatorEmote.BPRadialPopulatorEmote_C.SetupWidget
// 0x0018 (0x0018 - 0x0000)
struct BPRadialPopulatorEmote_C_SetupWidget final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorEmote_C_SetupWidget) == 0x000008, "Wrong alignment on BPRadialPopulatorEmote_C_SetupWidget");
static_assert(sizeof(BPRadialPopulatorEmote_C_SetupWidget) == 0x000018, "Wrong size on BPRadialPopulatorEmote_C_SetupWidget");
static_assert(offsetof(BPRadialPopulatorEmote_C_SetupWidget, Widget) == 0x000000, "Member 'BPRadialPopulatorEmote_C_SetupWidget::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_SetupWidget, RadialMenu) == 0x000008, "Member 'BPRadialPopulatorEmote_C_SetupWidget::RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorEmote_C_SetupWidget, Model) == 0x000010, "Member 'BPRadialPopulatorEmote_C_SetupWidget::Model' has a wrong offset!");

}

