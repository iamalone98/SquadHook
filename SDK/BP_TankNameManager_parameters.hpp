#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_TankNameManager

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_TankNameManager.BP_TankNameManager_C.ExecuteUbergraph_BP_TankNameManager
// 0x0008 (0x0008 - 0x0000)
struct BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager) == 0x000004, "Wrong alignment on BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager");
static_assert(sizeof(BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager) == 0x000008, "Wrong size on BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager");
static_assert(offsetof(BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager, EntryPoint) == 0x000000, "Member 'BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager, CallFunc_HasAuthority_ReturnValue) == 0x000004, "Member 'BP_TankNameManager_C_ExecuteUbergraph_BP_TankNameManager::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");

// Function BP_TankNameManager.BP_TankNameManager_C.Populate And Randomize List
// 0x0014 (0x0014 - 0x0000)
struct BP_TankNameManager_C_Populate_And_Randomize_List final
{
public:
	int32                                         Temp_int_Variable;                                 // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4B8C[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B8D[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_TankNameManager_C_Populate_And_Randomize_List) == 0x000004, "Wrong alignment on BP_TankNameManager_C_Populate_And_Randomize_List");
static_assert(sizeof(BP_TankNameManager_C_Populate_And_Randomize_List) == 0x000014, "Wrong size on BP_TankNameManager_C_Populate_And_Randomize_List");
static_assert(offsetof(BP_TankNameManager_C_Populate_And_Randomize_List, Temp_int_Variable) == 0x000000, "Member 'BP_TankNameManager_C_Populate_And_Randomize_List::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Populate_And_Randomize_List, CallFunc_Conv_IntToByte_ReturnValue) == 0x000004, "Member 'BP_TankNameManager_C_Populate_And_Randomize_List::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Populate_And_Randomize_List, CallFunc_Array_Add_ReturnValue) == 0x000008, "Member 'BP_TankNameManager_C_Populate_And_Randomize_List::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Populate_And_Randomize_List, CallFunc_LessEqual_IntInt_ReturnValue) == 0x00000C, "Member 'BP_TankNameManager_C_Populate_And_Randomize_List::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Populate_And_Randomize_List, CallFunc_Add_IntInt_ReturnValue) == 0x000010, "Member 'BP_TankNameManager_C_Populate_And_Randomize_List::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");

// Function BP_TankNameManager.BP_TankNameManager_C.Query Name
// 0x0018 (0x0018 - 0x0000)
struct BP_TankNameManager_C_Query_Name final
{
public:
	const class UBP_TurretTankNameGenerator_C*    ItemToFind;                                        // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, InstancedReference, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Output;                                            // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4B8E[0x3];                                     // 0x0009(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Find_ReturnValue;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         CallFunc_Array_Get_Item;                           // 0x0015(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_TankNameManager_C_Query_Name) == 0x000008, "Wrong alignment on BP_TankNameManager_C_Query_Name");
static_assert(sizeof(BP_TankNameManager_C_Query_Name) == 0x000018, "Wrong size on BP_TankNameManager_C_Query_Name");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, ItemToFind) == 0x000000, "Member 'BP_TankNameManager_C_Query_Name::ItemToFind' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, Output) == 0x000008, "Member 'BP_TankNameManager_C_Query_Name::Output' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, CallFunc_Array_Length_ReturnValue) == 0x00000C, "Member 'BP_TankNameManager_C_Query_Name::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, CallFunc_Array_Find_ReturnValue) == 0x000010, "Member 'BP_TankNameManager_C_Query_Name::CallFunc_Array_Find_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, CallFunc_Greater_IntInt_ReturnValue) == 0x000014, "Member 'BP_TankNameManager_C_Query_Name::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Query_Name, CallFunc_Array_Get_Item) == 0x000015, "Member 'BP_TankNameManager_C_Query_Name::CallFunc_Array_Get_Item' has a wrong offset!");

// Function BP_TankNameManager.BP_TankNameManager_C.Register Turret
// 0x0010 (0x0010 - 0x0000)
struct BP_TankNameManager_C_Register_Turret final
{
public:
	const class UBP_TurretTankNameGenerator_C*    Component;                                         // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, InstancedReference, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_AddUnique_ReturnValue;              // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_TankNameManager_C_Register_Turret) == 0x000008, "Wrong alignment on BP_TankNameManager_C_Register_Turret");
static_assert(sizeof(BP_TankNameManager_C_Register_Turret) == 0x000010, "Wrong size on BP_TankNameManager_C_Register_Turret");
static_assert(offsetof(BP_TankNameManager_C_Register_Turret, Component) == 0x000000, "Member 'BP_TankNameManager_C_Register_Turret::Component' has a wrong offset!");
static_assert(offsetof(BP_TankNameManager_C_Register_Turret, CallFunc_Array_AddUnique_ReturnValue) == 0x000008, "Member 'BP_TankNameManager_C_Register_Turret::CallFunc_Array_AddUnique_ReturnValue' has a wrong offset!");

}
