#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GoToFortificationMenu

#include "Basic.hpp"

#include "ESQDeployableTag_structs.hpp"
#include "SQDeployableGroupingStrategy_structs.hpp"


namespace SDK::Params
{

// Function BP_GoToFortificationMenu.BP_GoToFortificationMenu_C.ExecuteUbergraph_BP_GoToFortificationMenu
// 0x0108 (0x0108 - 0x0000)
struct BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_True_if_break_was_hit_Variable;          // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31BA[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31BB[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRadialButton*                        K2Node_Event_Widget;                               // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      K2Node_Event_Menu;                                 // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                K2Node_Event_Context;                              // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQDeployableTag                              Temp_byte_Variable;                                // 0x0030(0x0001)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31BC[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x004A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31BD[0x5];                                     // 0x004B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQFactionSetup_C*                   K2Node_DynamicCast_AsBP_SQFaction_Setup;           // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_TryGetDeployableGroupingStrategies_Success; // 0x0059(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31BE[0x6];                                     // 0x005A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQDeployableGroupingStrategy>  CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies; // 0x0060(0x0010)(ReferenceParm)
	struct FSQDeployableGroupingStrategy          CallFunc_Array_Get_Item;                           // 0x0070(0x0090)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0100(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0104(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0105(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Set_Contains_ReturnValue;                 // 0x0106(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu) == 0x000008, "Wrong alignment on BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu");
static_assert(sizeof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu) == 0x000108, "Wrong size on BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, EntryPoint) == 0x000000, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, Temp_bool_True_if_break_was_hit_Variable) == 0x000004, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::Temp_bool_True_if_break_was_hit_Variable' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Not_PreBool_ReturnValue) == 0x000005, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, Temp_int_Array_Index_Variable) == 0x000008, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, Temp_int_Loop_Counter_Variable) == 0x00000C, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Add_IntInt_ReturnValue) == 0x000010, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_Event_Widget) == 0x000018, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_Event_Widget' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_Event_Menu) == 0x000020, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_Event_Menu' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_Event_Context) == 0x000028, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_Event_Context' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, Temp_byte_Variable) == 0x000030, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_GetOwningPlayer_ReturnValue) == 0x000038, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000040, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_IsValid_ReturnValue) == 0x000049, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_IsValid_ReturnValue_1) == 0x00004A, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_DynamicCast_AsBP_SQFaction_Setup) == 0x000050, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_DynamicCast_AsBP_SQFaction_Setup' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, K2Node_DynamicCast_bSuccess_1) == 0x000058, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_TryGetDeployableGroupingStrategies_Success) == 0x000059, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_TryGetDeployableGroupingStrategies_Success' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies) == 0x000060, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_TryGetDeployableGroupingStrategies_Grouping_Strategies' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Array_Get_Item) == 0x000070, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Array_Length_ReturnValue) == 0x000100, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Less_IntInt_ReturnValue) == 0x000104, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_BooleanAND_ReturnValue) == 0x000105, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu, CallFunc_Set_Contains_ReturnValue) == 0x000106, "Member 'BP_GoToFortificationMenu_C_ExecuteUbergraph_BP_GoToFortificationMenu::CallFunc_Set_Contains_ReturnValue' has a wrong offset!");

// Function BP_GoToFortificationMenu.BP_GoToFortificationMenu_C.Populate
// 0x0018 (0x0018 - 0x0000)
struct BP_GoToFortificationMenu_C_Populate final
{
public:
	class USQRadialButton*                        Widget;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      Menu;                                              // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                Context;                                           // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GoToFortificationMenu_C_Populate) == 0x000008, "Wrong alignment on BP_GoToFortificationMenu_C_Populate");
static_assert(sizeof(BP_GoToFortificationMenu_C_Populate) == 0x000018, "Wrong size on BP_GoToFortificationMenu_C_Populate");
static_assert(offsetof(BP_GoToFortificationMenu_C_Populate, Widget) == 0x000000, "Member 'BP_GoToFortificationMenu_C_Populate::Widget' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_Populate, Menu) == 0x000008, "Member 'BP_GoToFortificationMenu_C_Populate::Menu' has a wrong offset!");
static_assert(offsetof(BP_GoToFortificationMenu_C_Populate, Context) == 0x000010, "Member 'BP_GoToFortificationMenu_C_Populate::Context' has a wrong offset!");

}

