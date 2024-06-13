#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RoleGroup

#include "Basic.hpp"

#include "SQRoleGroupingStrategy_structs.hpp"
#include "UMG_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function W_RoleGroup.W_RoleGroup_C.ExecuteUbergraph_W_RoleGroup
// 0x0068 (0x0068 - 0x0000)
struct W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsConfigured_ReturnValue;                 // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47D4[0x3];                                     // 0x0009(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47D5[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQAvailabilityState_Role>      K2Node_CustomEvent_In_Player_Role_States;          // 0x0018(0x0010)(ReferenceParm, ContainsInstancedReference)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0034(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsVisible_ReturnValue;                    // 0x0035(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47D6[0x2];                                     // 0x0036(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        K2Node_CustomEvent_In_Current_Role;                // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsVisible_ReturnValue_1;                  // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47D7[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleItem_C*                          CallFunc_Array_Get_Item;                           // 0x0048(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0054(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47D8[0x3];                                     // 0x0055(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47D9[0x4];                                     // 0x005C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleItem_C*                          CallFunc_Array_Get_Item_1;                         // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup) == 0x000008, "Wrong alignment on W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup");
static_assert(sizeof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup) == 0x000068, "Wrong size on W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, EntryPoint) == 0x000000, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_IsConfigured_ReturnValue) == 0x000008, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_IsConfigured_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Add_IntInt_ReturnValue) == 0x00000C, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, Temp_int_Array_Index_Variable) == 0x000010, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, K2Node_CustomEvent_In_Player_Role_States) == 0x000018, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::K2Node_CustomEvent_In_Player_Role_States' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, Temp_int_Loop_Counter_Variable_1) == 0x000028, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Array_Length_ReturnValue) == 0x00002C, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Add_IntInt_ReturnValue_1) == 0x000030, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Less_IntInt_ReturnValue) == 0x000034, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_IsVisible_ReturnValue) == 0x000035, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_IsVisible_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, K2Node_CustomEvent_In_Current_Role) == 0x000038, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::K2Node_CustomEvent_In_Current_Role' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_IsVisible_ReturnValue_1) == 0x000040, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_IsVisible_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Array_Get_Item) == 0x000048, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Array_Length_ReturnValue_1) == 0x000050, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Less_IntInt_ReturnValue_1) == 0x000054, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, Temp_int_Array_Index_Variable_1) == 0x000058, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup, CallFunc_Array_Get_Item_1) == 0x000060, "Member 'W_RoleGroup_C_ExecuteUbergraph_W_RoleGroup::CallFunc_Array_Get_Item_1' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.OnRoleChange
// 0x0008 (0x0008 - 0x0000)
struct W_RoleGroup_C_OnRoleChange final
{
public:
	class USQRoleSettings*                        In_Current_Role;                                   // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RoleGroup_C_OnRoleChange) == 0x000008, "Wrong alignment on W_RoleGroup_C_OnRoleChange");
static_assert(sizeof(W_RoleGroup_C_OnRoleChange) == 0x000008, "Wrong size on W_RoleGroup_C_OnRoleChange");
static_assert(offsetof(W_RoleGroup_C_OnRoleChange, In_Current_Role) == 0x000000, "Member 'W_RoleGroup_C_OnRoleChange::In_Current_Role' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.OnTick
// 0x0010 (0x0010 - 0x0000)
struct W_RoleGroup_C_OnTick final
{
public:
	TArray<struct FSQAvailabilityState_Role>      In_Player_Role_States;                             // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, ContainsInstancedReference)
};
static_assert(alignof(W_RoleGroup_C_OnTick) == 0x000008, "Wrong alignment on W_RoleGroup_C_OnTick");
static_assert(sizeof(W_RoleGroup_C_OnTick) == 0x000010, "Wrong size on W_RoleGroup_C_OnTick");
static_assert(offsetof(W_RoleGroup_C_OnTick, In_Player_Role_States) == 0x000000, "Member 'W_RoleGroup_C_OnTick::In_Player_Role_States' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.HasTagGrouping
// 0x01A0 (0x01A0 - 0x0000)
struct W_RoleGroup_C_HasTagGrouping final
{
public:
	class UBP_SQRoleSettings_C*                   InRoleSetting;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ShouldBeGrouped;                                   // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47DA[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQRoleGroupingStrategy                OutTagGroupingStrategy;                            // 0x0010(0x00A0)(Parm, OutParm, HasGetValueTypeHash)
	TArray<struct FSQRoleGroupingStrategy>        L_GroupingTags;                                    // 0x00B0(0x0010)(Edit, BlueprintVisible)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x00C0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x00C8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47DB[0x4];                                     // 0x00CC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQRoleGroupingStrategy                CallFunc_Array_Get_Item;                           // 0x00D0(0x00A0)(HasGetValueTypeHash)
	class UBP_SQFactionSetup_C*                   K2Node_DynamicCast_AsBP_SQFaction_Setup;           // 0x0170(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0178(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_TryGetRoleGroupingTags_OutSuccess;        // 0x0179(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47DC[0x6];                                     // 0x017A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQRoleGroupingStrategy>        CallFunc_TryGetRoleGroupingTags_OutGroupTags;      // 0x0180(0x0010)(ReferenceParm)
	bool                                          CallFunc_IsConcernedByStrategy_IsConcernedByStrategy; // 0x0190(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47DD[0x3];                                     // 0x0191(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0194(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0198(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_RoleGroup_C_HasTagGrouping) == 0x000008, "Wrong alignment on W_RoleGroup_C_HasTagGrouping");
static_assert(sizeof(W_RoleGroup_C_HasTagGrouping) == 0x0001A0, "Wrong size on W_RoleGroup_C_HasTagGrouping");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, InRoleSetting) == 0x000000, "Member 'W_RoleGroup_C_HasTagGrouping::InRoleSetting' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, ShouldBeGrouped) == 0x000008, "Member 'W_RoleGroup_C_HasTagGrouping::ShouldBeGrouped' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, OutTagGroupingStrategy) == 0x000010, "Member 'W_RoleGroup_C_HasTagGrouping::OutTagGroupingStrategy' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, L_GroupingTags) == 0x0000B0, "Member 'W_RoleGroup_C_HasTagGrouping::L_GroupingTags' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, Temp_int_Array_Index_Variable) == 0x0000C0, "Member 'W_RoleGroup_C_HasTagGrouping::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, Temp_int_Loop_Counter_Variable) == 0x0000C4, "Member 'W_RoleGroup_C_HasTagGrouping::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_Add_IntInt_ReturnValue) == 0x0000C8, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_Array_Get_Item) == 0x0000D0, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, K2Node_DynamicCast_AsBP_SQFaction_Setup) == 0x000170, "Member 'W_RoleGroup_C_HasTagGrouping::K2Node_DynamicCast_AsBP_SQFaction_Setup' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, K2Node_DynamicCast_bSuccess) == 0x000178, "Member 'W_RoleGroup_C_HasTagGrouping::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_TryGetRoleGroupingTags_OutSuccess) == 0x000179, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_TryGetRoleGroupingTags_OutSuccess' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_TryGetRoleGroupingTags_OutGroupTags) == 0x000180, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_TryGetRoleGroupingTags_OutGroupTags' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_IsConcernedByStrategy_IsConcernedByStrategy) == 0x000190, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_IsConcernedByStrategy_IsConcernedByStrategy' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_Array_Length_ReturnValue) == 0x000194, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_HasTagGrouping, CallFunc_Less_IntInt_ReturnValue) == 0x000198, "Member 'W_RoleGroup_C_HasTagGrouping::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.Populate List
// 0x0180 (0x0180 - 0x0000)
struct W_RoleGroup_C_Populate_List final
{
public:
	bool                                          L_Has_Roles;                                       // 0x0000(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47DE[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47DF[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47E0[0x3];                                     // 0x0015(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelWidget*                           CallFunc_Get_Role_Panel_RoleBox;                   // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_RoleItem_C*                          CallFunc_Create_ReturnValue;                       // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47E1[0x6];                                     // 0x0032(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue;                     // 0x0038(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_47E2[0x4];                                     // 0x0044(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQAvailabilityState_Role>      CallFunc_GetRoles_OutRoles;                        // 0x0048(0x0010)(ReferenceParm, ContainsInstancedReference)
	class UPanelWidget*                           CallFunc_Get_Role_Panel_RoleBox_1;                 // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQAvailabilityState_Role              CallFunc_Array_Get_Item;                           // 0x0060(0x0058)(ContainsInstancedReference)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00BC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E3[0x3];                                     // 0x00BD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasTagGrouping_ShouldBeGrouped;           // 0x00C9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E4[0x6];                                     // 0x00CA(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQRoleGroupingStrategy                CallFunc_HasTagGrouping_OutTagGroupingStrategy;    // 0x00D0(0x00A0)(HasGetValueTypeHash)
	bool                                          CallFunc_IsConcernedByStrategy_IsConcernedByStrategy; // 0x0170(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_SearchTagGroup_Out_Success;               // 0x0171(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E5[0x6];                                     // 0x0172(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleItem_C*                          CallFunc_SearchTagGroup_Out_Item;                  // 0x0178(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RoleGroup_C_Populate_List) == 0x000008, "Wrong alignment on W_RoleGroup_C_Populate_List");
static_assert(sizeof(W_RoleGroup_C_Populate_List) == 0x000180, "Wrong size on W_RoleGroup_C_Populate_List");
static_assert(offsetof(W_RoleGroup_C_Populate_List, L_Has_Roles) == 0x000000, "Member 'W_RoleGroup_C_Populate_List::L_Has_Roles' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, Temp_int_Array_Index_Variable) == 0x000004, "Member 'W_RoleGroup_C_Populate_List::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, Temp_int_Loop_Counter_Variable) == 0x000008, "Member 'W_RoleGroup_C_Populate_List::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, Temp_byte_Variable) == 0x00000C, "Member 'W_RoleGroup_C_Populate_List::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Add_IntInt_ReturnValue) == 0x000010, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, Temp_byte_Variable_1) == 0x000014, "Member 'W_RoleGroup_C_Populate_List::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_GetOwningPlayer_ReturnValue) == 0x000018, "Member 'W_RoleGroup_C_Populate_List::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Get_Role_Panel_RoleBox) == 0x000020, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Get_Role_Panel_RoleBox' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Create_ReturnValue) == 0x000028, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, Temp_bool_Variable) == 0x000030, "Member 'W_RoleGroup_C_Populate_List::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, K2Node_Select_Default) == 0x000031, "Member 'W_RoleGroup_C_Populate_List::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_AddChild_ReturnValue) == 0x000038, "Member 'W_RoleGroup_C_Populate_List::CallFunc_AddChild_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Array_Add_ReturnValue) == 0x000040, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_GetRoles_OutRoles) == 0x000048, "Member 'W_RoleGroup_C_Populate_List::CallFunc_GetRoles_OutRoles' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Get_Role_Panel_RoleBox_1) == 0x000058, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Get_Role_Panel_RoleBox_1' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Array_Get_Item) == 0x000060, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Array_Length_ReturnValue) == 0x0000B8, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_Less_IntInt_ReturnValue) == 0x0000BC, "Member 'W_RoleGroup_C_Populate_List::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x0000C0, "Member 'W_RoleGroup_C_Populate_List::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, K2Node_DynamicCast_bSuccess) == 0x0000C8, "Member 'W_RoleGroup_C_Populate_List::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_HasTagGrouping_ShouldBeGrouped) == 0x0000C9, "Member 'W_RoleGroup_C_Populate_List::CallFunc_HasTagGrouping_ShouldBeGrouped' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_HasTagGrouping_OutTagGroupingStrategy) == 0x0000D0, "Member 'W_RoleGroup_C_Populate_List::CallFunc_HasTagGrouping_OutTagGroupingStrategy' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_IsConcernedByStrategy_IsConcernedByStrategy) == 0x000170, "Member 'W_RoleGroup_C_Populate_List::CallFunc_IsConcernedByStrategy_IsConcernedByStrategy' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_SearchTagGroup_Out_Success) == 0x000171, "Member 'W_RoleGroup_C_Populate_List::CallFunc_SearchTagGroup_Out_Success' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_Populate_List, CallFunc_SearchTagGroup_Out_Item) == 0x000178, "Member 'W_RoleGroup_C_Populate_List::CallFunc_SearchTagGroup_Out_Item' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.Get Role Panel
// 0x0008 (0x0008 - 0x0000)
struct W_RoleGroup_C_Get_Role_Panel final
{
public:
	class UPanelWidget*                           Param_RoleBox;                                     // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RoleGroup_C_Get_Role_Panel) == 0x000008, "Wrong alignment on W_RoleGroup_C_Get_Role_Panel");
static_assert(sizeof(W_RoleGroup_C_Get_Role_Panel) == 0x000008, "Wrong size on W_RoleGroup_C_Get_Role_Panel");
static_assert(offsetof(W_RoleGroup_C_Get_Role_Panel, Param_RoleBox) == 0x000000, "Member 'W_RoleGroup_C_Get_Role_Panel::Param_RoleBox' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.IsPartOfThisGroup
// 0x0020 (0x0020 - 0x0000)
struct W_RoleGroup_C_IsPartOfThisGroup final
{
public:
	class USQRoleSettings*                        InRoleSetting;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Out_Part_Of_this_Group;                            // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E6[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsConcernedByStrategy_IsConcernedByStrategy; // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_RoleGroup_C_IsPartOfThisGroup) == 0x000008, "Wrong alignment on W_RoleGroup_C_IsPartOfThisGroup");
static_assert(sizeof(W_RoleGroup_C_IsPartOfThisGroup) == 0x000020, "Wrong size on W_RoleGroup_C_IsPartOfThisGroup");
static_assert(offsetof(W_RoleGroup_C_IsPartOfThisGroup, InRoleSetting) == 0x000000, "Member 'W_RoleGroup_C_IsPartOfThisGroup::InRoleSetting' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_IsPartOfThisGroup, Out_Part_Of_this_Group) == 0x000008, "Member 'W_RoleGroup_C_IsPartOfThisGroup::Out_Part_Of_this_Group' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_IsPartOfThisGroup, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x000010, "Member 'W_RoleGroup_C_IsPartOfThisGroup::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_IsPartOfThisGroup, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'W_RoleGroup_C_IsPartOfThisGroup::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_IsPartOfThisGroup, CallFunc_IsConcernedByStrategy_IsConcernedByStrategy) == 0x000019, "Member 'W_RoleGroup_C_IsPartOfThisGroup::CallFunc_IsConcernedByStrategy_IsConcernedByStrategy' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.GetMatchingRoleItem
// 0x0038 (0x0038 - 0x0000)
struct W_RoleGroup_C_GetMatchingRoleItem final
{
public:
	class USQRoleSettings*                        In_Role_Setting;                                   // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Out_Success;                                       // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E7[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleItem_C*                          Out_Role_Item;                                     // 0x0010(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_RoleItem_C*                          CallFunc_Array_Get_Item;                           // 0x0028(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsItemMatching_Is_Matching;               // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_RoleGroup_C_GetMatchingRoleItem) == 0x000008, "Wrong alignment on W_RoleGroup_C_GetMatchingRoleItem");
static_assert(sizeof(W_RoleGroup_C_GetMatchingRoleItem) == 0x000038, "Wrong size on W_RoleGroup_C_GetMatchingRoleItem");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, In_Role_Setting) == 0x000000, "Member 'W_RoleGroup_C_GetMatchingRoleItem::In_Role_Setting' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, Out_Success) == 0x000008, "Member 'W_RoleGroup_C_GetMatchingRoleItem::Out_Success' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, Out_Role_Item) == 0x000010, "Member 'W_RoleGroup_C_GetMatchingRoleItem::Out_Role_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, Temp_int_Array_Index_Variable) == 0x000018, "Member 'W_RoleGroup_C_GetMatchingRoleItem::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, Temp_int_Loop_Counter_Variable) == 0x00001C, "Member 'W_RoleGroup_C_GetMatchingRoleItem::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, CallFunc_Add_IntInt_ReturnValue) == 0x000020, "Member 'W_RoleGroup_C_GetMatchingRoleItem::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, CallFunc_Array_Length_ReturnValue) == 0x000024, "Member 'W_RoleGroup_C_GetMatchingRoleItem::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, CallFunc_Array_Get_Item) == 0x000028, "Member 'W_RoleGroup_C_GetMatchingRoleItem::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, CallFunc_Less_IntInt_ReturnValue) == 0x000030, "Member 'W_RoleGroup_C_GetMatchingRoleItem::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_GetMatchingRoleItem, CallFunc_IsItemMatching_Is_Matching) == 0x000031, "Member 'W_RoleGroup_C_GetMatchingRoleItem::CallFunc_IsItemMatching_Is_Matching' has a wrong offset!");

// Function W_RoleGroup.W_RoleGroup_C.SearchTagGroup
// 0x00D0 (0x00D0 - 0x0000)
struct W_RoleGroup_C_SearchTagGroup final
{
public:
	struct FSQRoleGroupingStrategy                In_Group_Strategy;                                 // 0x0000(0x00A0)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
	bool                                          Out_Success;                                       // 0x00A0(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E8[0x7];                                     // 0x00A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_RoleItem_C*                          Out_Item;                                          // 0x00A8(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x00B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00B4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_RoleItem_C*                          CallFunc_Array_Get_Item;                           // 0x00C0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasThisTagGrouping_OutHasMatchingTagGrouping; // 0x00C9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_RoleGroup_C_SearchTagGroup) == 0x000008, "Wrong alignment on W_RoleGroup_C_SearchTagGroup");
static_assert(sizeof(W_RoleGroup_C_SearchTagGroup) == 0x0000D0, "Wrong size on W_RoleGroup_C_SearchTagGroup");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, In_Group_Strategy) == 0x000000, "Member 'W_RoleGroup_C_SearchTagGroup::In_Group_Strategy' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, Out_Success) == 0x0000A0, "Member 'W_RoleGroup_C_SearchTagGroup::Out_Success' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, Out_Item) == 0x0000A8, "Member 'W_RoleGroup_C_SearchTagGroup::Out_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, Temp_int_Array_Index_Variable) == 0x0000B0, "Member 'W_RoleGroup_C_SearchTagGroup::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, Temp_int_Loop_Counter_Variable) == 0x0000B4, "Member 'W_RoleGroup_C_SearchTagGroup::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, CallFunc_Add_IntInt_ReturnValue) == 0x0000B8, "Member 'W_RoleGroup_C_SearchTagGroup::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, CallFunc_Array_Length_ReturnValue) == 0x0000BC, "Member 'W_RoleGroup_C_SearchTagGroup::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, CallFunc_Array_Get_Item) == 0x0000C0, "Member 'W_RoleGroup_C_SearchTagGroup::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, CallFunc_Less_IntInt_ReturnValue) == 0x0000C8, "Member 'W_RoleGroup_C_SearchTagGroup::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RoleGroup_C_SearchTagGroup, CallFunc_HasThisTagGrouping_OutHasMatchingTagGrouping) == 0x0000C9, "Member 'W_RoleGroup_C_SearchTagGroup::CallFunc_HasThisTagGrouping_OutHasMatchingTagGrouping' has a wrong offset!");

}

