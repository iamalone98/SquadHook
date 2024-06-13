#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RallyPointAction

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BP_RallyPointAction.BP_RallyPointAction_C.ExecuteUbergraph_BP_RallyPointAction
// 0x00F8 (0x00F8 - 0x0000)
struct BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_MakeStruct_LinearColor;                     // 0x000C(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_True_if_break_was_hit_Variable;          // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF8[0x3];                                     // 0x001D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           K2Node_MakeStruct_LinearColor_1;                   // 0x0020(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EF9[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_Event_Raidal_Menu;                          // 0x0038(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EFA[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EFB[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQPawnInventoryComponent*              CallFunc_GetInventory_ReturnValue;                 // 0x0068(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EFC[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQWeaponGroupData>             CallFunc_GetInventoryItemGroups_ReturnValue;       // 0x0080(0x0010)(ConstParm, ReferenceParm)
	struct FSQWeaponGroupData                     CallFunc_Array_Get_Item;                           // 0x0090(0x0028)()
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00BC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00BD(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EFD[0x2];                                     // 0x00BE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        CallFunc_GetCurrentRole_ReturnValue;               // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsSquadLeader_ReturnValue;                // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EFE[0x7];                                     // 0x00C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_FindValidWeaponByClass_ReturnValue;       // 0x00D0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Find_ReturnValue;                   // 0x00D8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Array_Contains_ReturnValue;               // 0x00DC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_SwitchWeaponDirectly_ReturnValue;         // 0x00DD(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EFF[0x2];                                     // 0x00DE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_EquippableRallyPoint_C*             K2Node_DynamicCast_AsBP_Equippable_Rally_Point;    // 0x00E0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00E8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsEquipped_ReturnValue;                   // 0x00E9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F00[0x2];                                     // 0x00EA(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetRearmItemCount_ReturnValue;            // 0x00EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction) == 0x000008, "Wrong alignment on BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction");
static_assert(sizeof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction) == 0x0000F8, "Wrong size on BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, EntryPoint) == 0x000000, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_MakeStruct_LinearColor) == 0x00000C, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_MakeStruct_LinearColor' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, Temp_bool_True_if_break_was_hit_Variable) == 0x00001C, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::Temp_bool_True_if_break_was_hit_Variable' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_MakeStruct_LinearColor_1) == 0x000020, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_MakeStruct_LinearColor_1' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Not_PreBool_ReturnValue) == 0x000030, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_Event_Raidal_Menu) == 0x000038, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_Event_Raidal_Menu' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_GetOwningPlayer_ReturnValue) == 0x000040, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, Temp_int_Array_Index_Variable) == 0x000048, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_K2_GetPawn_ReturnValue) == 0x000050, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_AsSQSoldier) == 0x000058, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_bSuccess) == 0x000060, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_GetInventory_ReturnValue) == 0x000068, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_GetInventory_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000070, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_bSuccess_1) == 0x000078, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_GetInventoryItemGroups_ReturnValue) == 0x000080, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_GetInventoryItemGroups_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Array_Get_Item) == 0x000090, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Array_Length_ReturnValue) == 0x0000B8, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Less_IntInt_ReturnValue) == 0x0000BC, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_BooleanAND_ReturnValue) == 0x0000BD, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_GetCurrentRole_ReturnValue) == 0x0000C0, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_GetCurrentRole_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_IsSquadLeader_ReturnValue) == 0x0000C8, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_IsSquadLeader_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_FindValidWeaponByClass_ReturnValue) == 0x0000D0, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_FindValidWeaponByClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Array_Find_ReturnValue) == 0x0000D8, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Array_Find_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Array_Contains_ReturnValue) == 0x0000DC, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Array_Contains_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_SwitchWeaponDirectly_ReturnValue) == 0x0000DD, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_SwitchWeaponDirectly_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_AsBP_Equippable_Rally_Point) == 0x0000E0, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_AsBP_Equippable_Rally_Point' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, K2Node_DynamicCast_bSuccess_2) == 0x0000E8, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_IsEquipped_ReturnValue) == 0x0000E9, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_IsEquipped_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_GetRearmItemCount_ReturnValue) == 0x0000EC, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_GetRearmItemCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction, CallFunc_Greater_IntInt_ReturnValue) == 0x0000F0, "Member 'BP_RallyPointAction_C_ExecuteUbergraph_BP_RallyPointAction::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");

// Function BP_RallyPointAction.BP_RallyPointAction_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_RallyPointAction_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Raidal_Menu;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_RallyPointAction_C_OnClicked) == 0x000008, "Wrong alignment on BP_RallyPointAction_C_OnClicked");
static_assert(sizeof(BP_RallyPointAction_C_OnClicked) == 0x000008, "Wrong size on BP_RallyPointAction_C_OnClicked");
static_assert(offsetof(BP_RallyPointAction_C_OnClicked, Raidal_Menu) == 0x000000, "Member 'BP_RallyPointAction_C_OnClicked::Raidal_Menu' has a wrong offset!");

}
