#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialItemModel

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_RadialItemModel.BP_RadialItemModel_C.ExecuteUbergraph_BP_RadialItemModel
// 0x0030 (0x0030 - 0x0000)
struct BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3FC7[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_CustomEvent_Radial;                         // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_CustomEvent_Radial_1;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQRadialButton*                        K2Node_CustomEvent_Widget;                         // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_CustomEvent_Menu;                           // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                K2Node_CustomEvent_Context;                        // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel) == 0x000008, "Wrong alignment on BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel");
static_assert(sizeof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel) == 0x000030, "Wrong size on BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, EntryPoint) == 0x000000, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, K2Node_CustomEvent_Radial) == 0x000008, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::K2Node_CustomEvent_Radial' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, K2Node_CustomEvent_Radial_1) == 0x000010, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::K2Node_CustomEvent_Radial_1' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, K2Node_CustomEvent_Widget) == 0x000018, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::K2Node_CustomEvent_Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, K2Node_CustomEvent_Menu) == 0x000020, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::K2Node_CustomEvent_Menu' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel, K2Node_CustomEvent_Context) == 0x000028, "Member 'BP_RadialItemModel_C_ExecuteUbergraph_BP_RadialItemModel::K2Node_CustomEvent_Context' has a wrong offset!");

// Function BP_RadialItemModel.BP_RadialItemModel_C.OnReleased
// 0x0008 (0x0008 - 0x0000)
struct BP_RadialItemModel_C_OnReleased final
{
public:
	class UBaseRadialMenu_C*                      Radial;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialItemModel_C_OnReleased) == 0x000008, "Wrong alignment on BP_RadialItemModel_C_OnReleased");
static_assert(sizeof(BP_RadialItemModel_C_OnReleased) == 0x000008, "Wrong size on BP_RadialItemModel_C_OnReleased");
static_assert(offsetof(BP_RadialItemModel_C_OnReleased, Radial) == 0x000000, "Member 'BP_RadialItemModel_C_OnReleased::Radial' has a wrong offset!");

// Function BP_RadialItemModel.BP_RadialItemModel_C.Populate
// 0x0018 (0x0018 - 0x0000)
struct BP_RadialItemModel_C_Populate final
{
public:
	class USQRadialButton*                        Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      Menu;                                              // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                Context;                                           // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialItemModel_C_Populate) == 0x000008, "Wrong alignment on BP_RadialItemModel_C_Populate");
static_assert(sizeof(BP_RadialItemModel_C_Populate) == 0x000018, "Wrong size on BP_RadialItemModel_C_Populate");
static_assert(offsetof(BP_RadialItemModel_C_Populate, Widget) == 0x000000, "Member 'BP_RadialItemModel_C_Populate::Widget' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_Populate, Menu) == 0x000008, "Member 'BP_RadialItemModel_C_Populate::Menu' has a wrong offset!");
static_assert(offsetof(BP_RadialItemModel_C_Populate, Context) == 0x000010, "Member 'BP_RadialItemModel_C_Populate::Context' has a wrong offset!");

// Function BP_RadialItemModel.BP_RadialItemModel_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_RadialItemModel_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Radial;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RadialItemModel_C_OnClicked) == 0x000008, "Wrong alignment on BP_RadialItemModel_C_OnClicked");
static_assert(sizeof(BP_RadialItemModel_C_OnClicked) == 0x000008, "Wrong size on BP_RadialItemModel_C_OnClicked");
static_assert(offsetof(BP_RadialItemModel_C_OnClicked, Radial) == 0x000000, "Member 'BP_RadialItemModel_C_OnClicked::Radial' has a wrong offset!");

}
