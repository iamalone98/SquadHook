#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Menu_DeployableCategories

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "SQDeployableGroupingStrategy_structs.hpp"


namespace SDK::Params
{

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.ExecuteUbergraph_BP_Menu_DeployableCategories
// 0x0018 (0x0018 - 0x0000)
struct BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40D8[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_Event_BaseRadialMenu;                       // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GenerateChildDeployableGroups_Out_Widget_Count; // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRadialWidgetSizeEnum                       CallFunc_GenerateChildDeployableGroups_Out_Widget_Size; // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories");
static_assert(sizeof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories) == 0x000018, "Wrong size on BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories");
static_assert(offsetof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories, EntryPoint) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories, K2Node_Event_BaseRadialMenu) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories::K2Node_Event_BaseRadialMenu' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories, CallFunc_GenerateChildDeployableGroups_Out_Widget_Count) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories::CallFunc_GenerateChildDeployableGroups_Out_Widget_Count' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories, CallFunc_GenerateChildDeployableGroups_Out_Widget_Size) == 0x000014, "Member 'BP_Menu_DeployableCategories_C_ExecuteUbergraph_BP_Menu_DeployableCategories::CallFunc_GenerateChildDeployableGroups_Out_Widget_Size' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.CreateChildWidgets
// 0x0008 (0x0008 - 0x0000)
struct BP_Menu_DeployableCategories_C_CreateChildWidgets final
{
public:
	class UBaseRadialMenu_C*                      BaseRadialMenu;                                    // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_CreateChildWidgets) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_CreateChildWidgets");
static_assert(sizeof(BP_Menu_DeployableCategories_C_CreateChildWidgets) == 0x000008, "Wrong size on BP_Menu_DeployableCategories_C_CreateChildWidgets");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateChildWidgets, BaseRadialMenu) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_CreateChildWidgets::BaseRadialMenu' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.CreateCenter
// 0x0020 (0x0020 - 0x0000)
struct BP_Menu_DeployableCategories_C_CreateCenter final
{
public:
	class UBaseRadialMenu_C*                      Base_Radial_Menu;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBPRadialPopulatorIcon_C*               CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon; // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          CallFunc_CreateRadialChildWidget_CreatedWidget;    // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_CreateCenter) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_CreateCenter");
static_assert(sizeof(BP_Menu_DeployableCategories_C_CreateCenter) == 0x000020, "Wrong size on BP_Menu_DeployableCategories_C_CreateCenter");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateCenter, Base_Radial_Menu) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_CreateCenter::Base_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateCenter, CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_CreateCenter::CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateCenter, CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_CreateCenter::CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateCenter, CallFunc_CreateRadialChildWidget_CreatedWidget) == 0x000018, "Member 'BP_Menu_DeployableCategories_C_CreateCenter::CallFunc_CreateRadialChildWidget_CreatedWidget' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.InstantiateChildPopulator
// 0x0018 (0x0018 - 0x0000)
struct BP_Menu_DeployableCategories_C_InstantiateChildPopulator final
{
public:
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBPRadialPopulatorGotoDeployableGroup_C* K2Node_DynamicCast_AsBPRadial_Populator_Goto_Deployable_Group; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_InstantiateChildPopulator) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_InstantiateChildPopulator");
static_assert(sizeof(BP_Menu_DeployableCategories_C_InstantiateChildPopulator) == 0x000018, "Wrong size on BP_Menu_DeployableCategories_C_InstantiateChildPopulator");
static_assert(offsetof(BP_Menu_DeployableCategories_C_InstantiateChildPopulator, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_InstantiateChildPopulator::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_InstantiateChildPopulator, K2Node_DynamicCast_AsBPRadial_Populator_Goto_Deployable_Group) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_InstantiateChildPopulator::K2Node_DynamicCast_AsBPRadial_Populator_Goto_Deployable_Group' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_InstantiateChildPopulator, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_InstantiateChildPopulator::K2Node_DynamicCast_bSuccess' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.GenerateChildDeployableGroups
// 0x00E8 (0x00E8 - 0x0000)
struct BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups final
{
public:
	class UBaseRadialMenu_C*                      Base_Radial_Menu;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Out_Widget_Count;                                  // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRadialWidgetSizeEnum                       Out_Widget_Size;                                   // 0x000C(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRadialWidgetSizeEnum                       L_Widget_Size;                                     // 0x000D(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40D9[0x2];                                     // 0x000E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         L_GroupCount;                                      // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_CollectDeployableGroups_Success;          // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40DA[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQDeployableGroupingStrategy>  CallFunc_CollectDeployableGroups_Out_Groups;       // 0x0020(0x0010)(ReferenceParm)
	struct FSQDeployableGroupingStrategy          CallFunc_Array_Get_Item;                           // 0x0030(0x0090)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00C0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRadialWidgetSizeEnum                       CallFunc_DetermineWidgetSize_Out_Size;             // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40DB[0x3];                                     // 0x00C9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40DC[0x3];                                     // 0x00D1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x00D4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_GotoDeployableMenuActionModel_C*    CallFunc_SpawnObject_ReturnValue;                  // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          CallFunc_CreateRadialChildWidget_CreatedWidget;    // 0x00E0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups");
static_assert(sizeof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups) == 0x0000E8, "Wrong size on BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, Base_Radial_Menu) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::Base_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, Out_Widget_Count) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::Out_Widget_Count' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, Out_Widget_Size) == 0x00000C, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::Out_Widget_Size' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, L_Widget_Size) == 0x00000D, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::L_Widget_Size' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, L_GroupCount) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::L_GroupCount' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, Temp_int_Array_Index_Variable) == 0x000014, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_CollectDeployableGroups_Success) == 0x000018, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_CollectDeployableGroups_Success' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_CollectDeployableGroups_Out_Groups) == 0x000020, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_CollectDeployableGroups_Out_Groups' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_Array_Get_Item) == 0x000030, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_Array_Length_ReturnValue) == 0x0000C0, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_Array_Length_ReturnValue_1) == 0x0000C4, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_DetermineWidgetSize_Out_Size) == 0x0000C8, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_DetermineWidgetSize_Out_Size' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, Temp_int_Loop_Counter_Variable) == 0x0000CC, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_Less_IntInt_ReturnValue) == 0x0000D0, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_Add_IntInt_ReturnValue) == 0x0000D4, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_SpawnObject_ReturnValue) == 0x0000D8, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_SpawnObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups, CallFunc_CreateRadialChildWidget_CreatedWidget) == 0x0000E0, "Member 'BP_Menu_DeployableCategories_C_GenerateChildDeployableGroups::CallFunc_CreateRadialChildWidget_CreatedWidget' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.CreateBackButton
// 0x0028 (0x0028 - 0x0000)
struct BP_Menu_DeployableCategories_C_CreateBackButton final
{
public:
	class UBaseRadialMenu_C*                      Base_Radial_Menu;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         In_Widget_Count;                                   // 0x0008(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRadialWidgetSizeEnum                       In_Widget_Size;                                    // 0x000C(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40DD[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RadialItemModel_C*                  CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model; // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBPRadialPopulatorIcon_C*               CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon; // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQUserWidget*                          CallFunc_CreateRadialChildWidget_CreatedWidget;    // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_CreateBackButton) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_CreateBackButton");
static_assert(sizeof(BP_Menu_DeployableCategories_C_CreateBackButton) == 0x000028, "Wrong size on BP_Menu_DeployableCategories_C_CreateBackButton");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, Base_Radial_Menu) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::Base_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, In_Widget_Count) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::In_Widget_Count' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, In_Widget_Size) == 0x00000C, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::In_Widget_Size' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::CallFunc_GetModelReferencesFromClass_AsBP_Radial_Item_Model' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon) == 0x000018, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::CallFunc_GetModelReferencesFromClass_AsBPRadial_Populator_Icon' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CreateBackButton, CallFunc_CreateRadialChildWidget_CreatedWidget) == 0x000020, "Member 'BP_Menu_DeployableCategories_C_CreateBackButton::CallFunc_CreateRadialChildWidget_CreatedWidget' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.CollectDeployableGroups
// 0x0058 (0x0058 - 0x0000)
struct BP_Menu_DeployableCategories_C_CollectDeployableGroups final
{
public:
	class UBaseRadialMenu_C*                      Base_Radial_Menu;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Success;                                           // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40DE[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQDeployableGroupingStrategy>  Out_Groups;                                        // 0x0010(0x0010)(Parm, OutParm)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0032(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40DF[0x5];                                     // 0x0033(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQFactionSetup_C*                   K2Node_DynamicCast_AsBP_SQFaction_Setup;           // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_TryGetDeployableGroupingStrategies_Success; // 0x0041(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40E0[0x6];                                     // 0x0042(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQDeployableGroupingStrategy>  CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies; // 0x0048(0x0010)(ReferenceParm)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_CollectDeployableGroups) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_CollectDeployableGroups");
static_assert(sizeof(BP_Menu_DeployableCategories_C_CollectDeployableGroups) == 0x000058, "Wrong size on BP_Menu_DeployableCategories_C_CollectDeployableGroups");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, Base_Radial_Menu) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::Base_Radial_Menu' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, Success) == 0x000008, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::Success' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, Out_Groups) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::Out_Groups' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, CallFunc_GetOwningPlayer_ReturnValue) == 0x000020, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000028, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, K2Node_DynamicCast_bSuccess) == 0x000030, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, CallFunc_IsValid_ReturnValue) == 0x000031, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, CallFunc_IsValid_ReturnValue_1) == 0x000032, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, K2Node_DynamicCast_AsBP_SQFaction_Setup) == 0x000038, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::K2Node_DynamicCast_AsBP_SQFaction_Setup' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, CallFunc_TryGetDeployableGroupingStrategies_Success) == 0x000041, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::CallFunc_TryGetDeployableGroupingStrategies_Success' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_CollectDeployableGroups, CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies) == 0x000048, "Member 'BP_Menu_DeployableCategories_C_CollectDeployableGroups::CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies' has a wrong offset!");

// Function BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C.DetermineWidgetSize
// 0x0020 (0x0020 - 0x0000)
struct BP_Menu_DeployableCategories_C_DetermineWidgetSize final
{
public:
	TArray<struct FSQDeployableGroupingStrategy>  In_Groups;                                         // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	ESQRadialWidgetSizeEnum                       Out_Size;                                          // 0x0010(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40E1[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Menu_DeployableCategories_C_DetermineWidgetSize) == 0x000008, "Wrong alignment on BP_Menu_DeployableCategories_C_DetermineWidgetSize");
static_assert(sizeof(BP_Menu_DeployableCategories_C_DetermineWidgetSize) == 0x000020, "Wrong size on BP_Menu_DeployableCategories_C_DetermineWidgetSize");
static_assert(offsetof(BP_Menu_DeployableCategories_C_DetermineWidgetSize, In_Groups) == 0x000000, "Member 'BP_Menu_DeployableCategories_C_DetermineWidgetSize::In_Groups' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_DetermineWidgetSize, Out_Size) == 0x000010, "Member 'BP_Menu_DeployableCategories_C_DetermineWidgetSize::Out_Size' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_DetermineWidgetSize, CallFunc_Array_Length_ReturnValue) == 0x000014, "Member 'BP_Menu_DeployableCategories_C_DetermineWidgetSize::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_DetermineWidgetSize, CallFunc_Less_IntInt_ReturnValue) == 0x000018, "Member 'BP_Menu_DeployableCategories_C_DetermineWidgetSize::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Menu_DeployableCategories_C_DetermineWidgetSize, CallFunc_Less_IntInt_ReturnValue_1) == 0x000019, "Member 'BP_Menu_DeployableCategories_C_DetermineWidgetSize::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");

}

