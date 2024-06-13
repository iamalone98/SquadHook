#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Grid_ActionList_CO

#include "Basic.hpp"


namespace SDK::Params
{

// Function W_Grid_ActionList_CO.W_Grid_ActionList_CO_C.ExecuteUbergraph_W_Grid_ActionList_CO
// 0x0038 (0x0038 - 0x0000)
struct W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_Grid_Action_Command_C*               CallFunc_Create_ReturnValue;                       // 0x0018(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 CallFunc_Array_Get_Item;                           // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x002C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_45D3[0x3];                                     // 0x002D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UVerticalBoxSlot*                       CallFunc_AddChildToVerticalBox_ReturnValue;        // 0x0030(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO) == 0x000008, "Wrong alignment on W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO");
static_assert(sizeof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO) == 0x000038, "Wrong size on W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, EntryPoint) == 0x000000, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, Temp_int_Array_Index_Variable) == 0x000004, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, Temp_int_Loop_Counter_Variable) == 0x000008, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_Add_IntInt_ReturnValue) == 0x00000C, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_GetOwningPlayer_ReturnValue) == 0x000010, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_Create_ReturnValue) == 0x000018, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_Array_Get_Item) == 0x000020, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_Array_Length_ReturnValue) == 0x000028, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_Less_IntInt_ReturnValue) == 0x00002C, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO, CallFunc_AddChildToVerticalBox_ReturnValue) == 0x000030, "Member 'W_Grid_ActionList_CO_C_ExecuteUbergraph_W_Grid_ActionList_CO::CallFunc_AddChildToVerticalBox_ReturnValue' has a wrong offset!");

// Function W_Grid_ActionList_CO.W_Grid_ActionList_CO_C.Get Fireteam ID
// 0x0020 (0x0020 - 0x0000)
struct W_Grid_ActionList_CO_C_Get_Fireteam_ID final
{
public:
	int32                                         ID;                                                // 0x0000(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_45D4[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_45D5[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetFireTeamIndex_ReturnValue;             // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Grid_ActionList_CO_C_Get_Fireteam_ID) == 0x000008, "Wrong alignment on W_Grid_ActionList_CO_C_Get_Fireteam_ID");
static_assert(sizeof(W_Grid_ActionList_CO_C_Get_Fireteam_ID) == 0x000020, "Wrong size on W_Grid_ActionList_CO_C_Get_Fireteam_ID");
static_assert(offsetof(W_Grid_ActionList_CO_C_Get_Fireteam_ID, ID) == 0x000000, "Member 'W_Grid_ActionList_CO_C_Get_Fireteam_ID::ID' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_Get_Fireteam_ID, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_Grid_ActionList_CO_C_Get_Fireteam_ID::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_Get_Fireteam_ID, K2Node_DynamicCast_AsSQPlayer_State) == 0x000010, "Member 'W_Grid_ActionList_CO_C_Get_Fireteam_ID::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_Get_Fireteam_ID, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'W_Grid_ActionList_CO_C_Get_Fireteam_ID::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_Grid_ActionList_CO_C_Get_Fireteam_ID, CallFunc_GetFireTeamIndex_ReturnValue) == 0x00001C, "Member 'W_Grid_ActionList_CO_C_Get_Fireteam_ID::CallFunc_GetFireTeamIndex_ReturnValue' has a wrong offset!");

}

