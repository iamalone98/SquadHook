#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapLattice

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function W_MapLattice.W_MapLattice_C.ExecuteUbergraph_W_MapLattice
// 0x0060 (0x0060 - 0x0000)
struct W_MapLattice_C_ExecuteUbergraph_W_MapLattice final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_456F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class ASQAASGraph*>                    CallFunc_GetAllActorsOfClass_OutActors;            // 0x0008(0x0010)(ReferenceParm)
	class ASQAASGraph*                            CallFunc_Array_Get_Item;                           // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4570[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         CallFunc_Get_UI_Save_Data_UI_Save_Data;            // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_MakeStruct_LinearColor;                     // 0x0030(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_MakeStruct_LinearColor_1;                   // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_MakeStruct_LinearColor_2;                   // 0x0050(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice) == 0x000008, "Wrong alignment on W_MapLattice_C_ExecuteUbergraph_W_MapLattice");
static_assert(sizeof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice) == 0x000060, "Wrong size on W_MapLattice_C_ExecuteUbergraph_W_MapLattice");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, EntryPoint) == 0x000000, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, CallFunc_GetAllActorsOfClass_OutActors) == 0x000008, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::CallFunc_GetAllActorsOfClass_OutActors' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, CallFunc_Array_Get_Item) == 0x000018, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, CallFunc_Array_Length_ReturnValue) == 0x000020, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, CallFunc_Greater_IntInt_ReturnValue) == 0x000024, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, CallFunc_Get_UI_Save_Data_UI_Save_Data) == 0x000028, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::CallFunc_Get_UI_Save_Data_UI_Save_Data' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, K2Node_MakeStruct_LinearColor) == 0x000030, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::K2Node_MakeStruct_LinearColor' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, K2Node_MakeStruct_LinearColor_1) == 0x000040, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::K2Node_MakeStruct_LinearColor_1' has a wrong offset!");
static_assert(offsetof(W_MapLattice_C_ExecuteUbergraph_W_MapLattice, K2Node_MakeStruct_LinearColor_2) == 0x000050, "Member 'W_MapLattice_C_ExecuteUbergraph_W_MapLattice::K2Node_MakeStruct_LinearColor_2' has a wrong offset!");

}

