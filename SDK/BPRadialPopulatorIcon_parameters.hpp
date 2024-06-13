#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPRadialPopulatorIcon

#include "Basic.hpp"


namespace SDK::Params
{

// Function BPRadialPopulatorIcon.BPRadialPopulatorIcon_C.FinishWidgetSetup
// 0x0030 (0x0030 - 0x0000)
struct BPRadialPopulatorIcon_C_FinishWidgetSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  ActionModel;                                       // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQRadialButton*                        K2Node_DynamicCast_AsSQRadial_Button;              // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F44[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorIcon_C_FinishWidgetSetup) == 0x000008, "Wrong alignment on BPRadialPopulatorIcon_C_FinishWidgetSetup");
static_assert(sizeof(BPRadialPopulatorIcon_C_FinishWidgetSetup) == 0x000030, "Wrong size on BPRadialPopulatorIcon_C_FinishWidgetSetup");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, Widget) == 0x000000, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, RadialMenu) == 0x000008, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, ActionModel) == 0x000010, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::ActionModel' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, K2Node_DynamicCast_AsSQRadial_Button) == 0x000018, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::K2Node_DynamicCast_AsSQRadial_Button' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_FinishWidgetSetup, CallFunc_GetOwningPlayer_ReturnValue) == 0x000028, "Member 'BPRadialPopulatorIcon_C_FinishWidgetSetup::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");

// Function BPRadialPopulatorIcon.BPRadialPopulatorIcon_C.InitialSetup
// 0x0030 (0x0030 - 0x0000)
struct BPRadialPopulatorIcon_C_InitialSetup final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F45[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UIconRadialEntry_C*                     K2Node_DynamicCast_AsIcon_Radial_Entry;            // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BPRadialPopulatorIcon_C_InitialSetup) == 0x000008, "Wrong alignment on BPRadialPopulatorIcon_C_InitialSetup");
static_assert(sizeof(BPRadialPopulatorIcon_C_InitialSetup) == 0x000030, "Wrong size on BPRadialPopulatorIcon_C_InitialSetup");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, Widget) == 0x000000, "Member 'BPRadialPopulatorIcon_C_InitialSetup::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, Model) == 0x000008, "Member 'BPRadialPopulatorIcon_C_InitialSetup::Model' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, RadialMenu) == 0x000010, "Member 'BPRadialPopulatorIcon_C_InitialSetup::RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, CallFunc_IsValid_ReturnValue) == 0x000018, "Member 'BPRadialPopulatorIcon_C_InitialSetup::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, K2Node_DynamicCast_AsIcon_Radial_Entry) == 0x000020, "Member 'BPRadialPopulatorIcon_C_InitialSetup::K2Node_DynamicCast_AsIcon_Radial_Entry' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_InitialSetup, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'BPRadialPopulatorIcon_C_InitialSetup::K2Node_DynamicCast_bSuccess' has a wrong offset!");

// Function BPRadialPopulatorIcon.BPRadialPopulatorIcon_C.SetupWidget
// 0x0018 (0x0018 - 0x0000)
struct BPRadialPopulatorIcon_C_SetupWidget final
{
public:
	class USQUserWidget*                          Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  Model;                                             // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BPRadialPopulatorIcon_C_SetupWidget) == 0x000008, "Wrong alignment on BPRadialPopulatorIcon_C_SetupWidget");
static_assert(sizeof(BPRadialPopulatorIcon_C_SetupWidget) == 0x000018, "Wrong size on BPRadialPopulatorIcon_C_SetupWidget");
static_assert(offsetof(BPRadialPopulatorIcon_C_SetupWidget, Widget) == 0x000000, "Member 'BPRadialPopulatorIcon_C_SetupWidget::Widget' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_SetupWidget, RadialMenu) == 0x000008, "Member 'BPRadialPopulatorIcon_C_SetupWidget::RadialMenu' has a wrong offset!");
static_assert(offsetof(BPRadialPopulatorIcon_C_SetupWidget, Model) == 0x000010, "Member 'BPRadialPopulatorIcon_C_SetupWidget::Model' has a wrong offset!");

}
