#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridButton_CommandCategory

#include "Basic.hpp"


namespace SDK::Params
{

// Function W_GridButton_CommandCategory.W_GridButton_CommandCategory_C.ExecuteUbergraph_W_GridButton_CommandCategory
// 0x0060 (0x0060 - 0x0000)
struct W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Temp_object_Variable;                              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Temp_object_Variable_1;                            // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             K2Node_Select_Default;                             // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_450E[0x3];                                     // 0x0031(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         K2Node_CustomEvent_Category_ID;                    // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller_1;        // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_450F[0x6];                                     // 0x004A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_Grid_ActionList_CO_C*                K2Node_DynamicCast_AsW_Grid_Action_List_CO;        // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory) == 0x000008, "Wrong alignment on W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory");
static_assert(sizeof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory) == 0x000060, "Wrong size on W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, EntryPoint) == 0x000000, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, Temp_int_Variable) == 0x000004, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, Temp_object_Variable) == 0x000008, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::Temp_object_Variable' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, Temp_object_Variable_1) == 0x000010, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::Temp_object_Variable_1' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_Select_Default) == 0x000018, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, CallFunc_GetOwningPlayer_ReturnValue) == 0x000020, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000028, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_bSuccess) == 0x000030, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_CustomEvent_Category_ID) == 0x000034, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_CustomEvent_Category_ID' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000038, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_AsSQPlayer_Controller_1) == 0x000040, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_AsSQPlayer_Controller_1' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_bSuccess_1) == 0x000048, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000049, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_AsW_Grid_Action_List_CO) == 0x000050, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_AsW_Grid_Action_List_CO' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory, K2Node_DynamicCast_bSuccess_2) == 0x000058, "Member 'W_GridButton_CommandCategory_C_ExecuteUbergraph_W_GridButton_CommandCategory::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");

// Function W_GridButton_CommandCategory.W_GridButton_CommandCategory_C.Init Actions
// 0x0004 (0x0004 - 0x0000)
struct W_GridButton_CommandCategory_C_Init_Actions final
{
public:
	int32                                         Param_Category_ID;                                 // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_GridButton_CommandCategory_C_Init_Actions) == 0x000004, "Wrong alignment on W_GridButton_CommandCategory_C_Init_Actions");
static_assert(sizeof(W_GridButton_CommandCategory_C_Init_Actions) == 0x000004, "Wrong size on W_GridButton_CommandCategory_C_Init_Actions");
static_assert(offsetof(W_GridButton_CommandCategory_C_Init_Actions, Param_Category_ID) == 0x000000, "Member 'W_GridButton_CommandCategory_C_Init_Actions::Param_Category_ID' has a wrong offset!");

// Function W_GridButton_CommandCategory.W_GridButton_CommandCategory_C.Get Actions
// 0x0018 (0x0018 - 0x0000)
struct W_GridButton_CommandCategory_C_Get_Actions final
{
public:
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4510[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TSubclassOf<class USQGridData_CommandOption>> CallFunc_GetCommandActionsById_ReturnValue;        // 0x0008(0x0010)(ReferenceParm)
};
static_assert(alignof(W_GridButton_CommandCategory_C_Get_Actions) == 0x000008, "Wrong alignment on W_GridButton_CommandCategory_C_Get_Actions");
static_assert(sizeof(W_GridButton_CommandCategory_C_Get_Actions) == 0x000018, "Wrong size on W_GridButton_CommandCategory_C_Get_Actions");
static_assert(offsetof(W_GridButton_CommandCategory_C_Get_Actions, CallFunc_Conv_IntToByte_ReturnValue) == 0x000000, "Member 'W_GridButton_CommandCategory_C_Get_Actions::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_GridButton_CommandCategory_C_Get_Actions, CallFunc_GetCommandActionsById_ReturnValue) == 0x000008, "Member 'W_GridButton_CommandCategory_C_Get_Actions::CallFunc_GetCommandActionsById_ReturnValue' has a wrong offset!");

}
