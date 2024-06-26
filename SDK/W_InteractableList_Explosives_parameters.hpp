#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Explosives

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.ExecuteUbergraph_W_InteractableList_Explosives
// 0x0044 (0x0044 - 0x0000)
struct W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CE6[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0008(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives) == 0x000004, "Wrong alignment on W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives");
static_assert(sizeof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives) == 0x000044, "Wrong size on W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives");
static_assert(offsetof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives, EntryPoint) == 0x000000, "Member 'W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives, K2Node_Event_MyGeometry) == 0x000008, "Member 'W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives, K2Node_Event_InDeltaTime) == 0x000040, "Member 'W_InteractableList_Explosives_C_ExecuteUbergraph_W_InteractableList_Explosives::K2Node_Event_InDeltaTime' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_InteractableList_Explosives_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Explosives_C_Tick) == 0x000004, "Wrong alignment on W_InteractableList_Explosives_C_Tick");
static_assert(sizeof(W_InteractableList_Explosives_C_Tick) == 0x00003C, "Wrong size on W_InteractableList_Explosives_C_Tick");
static_assert(offsetof(W_InteractableList_Explosives_C_Tick, MyGeometry) == 0x000000, "Member 'W_InteractableList_Explosives_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Tick, InDeltaTime) == 0x000038, "Member 'W_InteractableList_Explosives_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Soldier Has Shovel
// 0x00E8 (0x00E8 - 0x0000)
struct W_InteractableList_Explosives_C_Soldier_Has_Shovel final
{
public:
	bool                                          Shovel_Equipped;                                   // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Owns_Shovel;                                       // 0x0001(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CE7[0x6];                                     // 0x0002(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQPawnInventoryComponent*              L_Inventory;                                       // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FSQWeaponGroupData>             CallFunc_GetInventoryItemGroups_ReturnValue;       // 0x0028(0x0010)(ConstParm, ReferenceParm)
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQWeaponGroupData                     CallFunc_Array_Get_Item;                           // 0x0040(0x0028)()
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CE8[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_Array_Get_Item_1;                         // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CE9[0x7];                                     // 0x0081(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQItemStaticInfo*                      CallFunc_GetItemStaticInfo_ReturnValue;            // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQShovelStaticInfo*                    K2Node_DynamicCast_AsSQShovel_Static_Info;         // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CEA[0x3];                                     // 0x0099(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00A9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CEB[0x6];                                     // 0x00AA(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_GetCurrentWeapon_ReturnValue;             // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x00B8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CEC[0x7];                                     // 0x00B9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQItemStaticInfo*                      CallFunc_GetItemStaticInfo_ReturnValue_1;          // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQShovelStaticInfo*                    K2Node_DynamicCast_AsSQShovel_Static_Info_1;       // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CED[0x7];                                     // 0x00D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQPawnInventoryComponent*              CallFunc_GetInventory_ReturnValue;                 // 0x00D8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x00E0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x00E4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x00E5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_InteractableList_Explosives_C_Soldier_Has_Shovel) == 0x000008, "Wrong alignment on W_InteractableList_Explosives_C_Soldier_Has_Shovel");
static_assert(sizeof(W_InteractableList_Explosives_C_Soldier_Has_Shovel) == 0x0000E8, "Wrong size on W_InteractableList_Explosives_C_Soldier_Has_Shovel");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Shovel_Equipped) == 0x000000, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Shovel_Equipped' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Owns_Shovel) == 0x000001, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Owns_Shovel' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, L_Inventory) == 0x000008, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::L_Inventory' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Temp_int_Array_Index_Variable) == 0x000010, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Temp_int_Loop_Counter_Variable) == 0x000014, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Add_IntInt_ReturnValue) == 0x000018, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Temp_int_Loop_Counter_Variable_1) == 0x00001C, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Add_IntInt_ReturnValue_1) == 0x000020, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, Temp_int_Array_Index_Variable_1) == 0x000024, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetInventoryItemGroups_ReturnValue) == 0x000028, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetInventoryItemGroups_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetSquadPlayerController_Return_Value) == 0x000038, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Array_Get_Item) == 0x000040, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_K2_GetPawn_ReturnValue) == 0x000068, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_IsValid_ReturnValue) == 0x000070, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Array_Get_Item_1) == 0x000078, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_IsValid_ReturnValue_1) == 0x000080, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetItemStaticInfo_ReturnValue) == 0x000088, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetItemStaticInfo_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_AsSQShovel_Static_Info) == 0x000090, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_AsSQShovel_Static_Info' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_bSuccess) == 0x000098, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Array_Length_ReturnValue) == 0x00009C, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_AsSQSoldier) == 0x0000A0, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_bSuccess_1) == 0x0000A8, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Less_IntInt_ReturnValue) == 0x0000A9, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetCurrentWeapon_ReturnValue) == 0x0000B0, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetCurrentWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_IsValid_ReturnValue_2) == 0x0000B8, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetItemStaticInfo_ReturnValue_1) == 0x0000C0, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetItemStaticInfo_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_AsSQShovel_Static_Info_1) == 0x0000C8, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_AsSQShovel_Static_Info_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, K2Node_DynamicCast_bSuccess_2) == 0x0000D0, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_GetInventory_ReturnValue) == 0x0000D8, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_GetInventory_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Array_Length_ReturnValue_1) == 0x0000E0, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_IsValid_ReturnValue_3) == 0x0000E4, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Soldier_Has_Shovel, CallFunc_Less_IntInt_ReturnValue_1) == 0x0000E5, "Member 'W_InteractableList_Explosives_C_Soldier_Has_Shovel::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Is Deployable Built
// 0x0018 (0x0018 - 0x0000)
struct W_InteractableList_Explosives_C_Is_Deployable_Built final
{
public:
	bool                                          Is_Built;                                          // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Full_Health;                                       // 0x0001(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CEE[0x6];                                     // 0x0002(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQDeployable*                          K2Node_DynamicCast_AsSQDeployable;                 // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESQBuildState                                 CallFunc_GetBuildState_ReturnValue;                // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NearlyEqual_FloatFloat_ReturnValue;       // 0x0013(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_InteractableList_Explosives_C_Is_Deployable_Built) == 0x000008, "Wrong alignment on W_InteractableList_Explosives_C_Is_Deployable_Built");
static_assert(sizeof(W_InteractableList_Explosives_C_Is_Deployable_Built) == 0x000018, "Wrong size on W_InteractableList_Explosives_C_Is_Deployable_Built");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, Is_Built) == 0x000000, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::Is_Built' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, Full_Health) == 0x000001, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::Full_Health' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, K2Node_DynamicCast_AsSQDeployable) == 0x000008, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::K2Node_DynamicCast_AsSQDeployable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, CallFunc_GetBuildState_ReturnValue) == 0x000012, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::CallFunc_GetBuildState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, CallFunc_NearlyEqual_FloatFloat_ReturnValue) == 0x000013, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::CallFunc_NearlyEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Is_Deployable_Built, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000014, "Member 'W_InteractableList_Explosives_C_Is_Deployable_Built::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Create Shovel Items
// 0x00A0 (0x00A0 - 0x0000)
struct W_InteractableList_Explosives_C_Create_Shovel_Items final
{
public:
	TArray<struct FSQUsableWidgetData>            L_Interact_Data_Array;                             // 0x0000(0x0010)(Edit, BlueprintVisible)
	bool                                          Temp_bool_Variable;                                // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Is_Deployable_Built_Is_Built;             // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Is_Deployable_Built_Full_Health;          // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4CEF[0x5];                                     // 0x0013(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0018(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0058(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0068(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0080(0x0018)()
	bool                                          CallFunc_Soldier_Has_Shovel_Shovel_Equipped;       // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Soldier_Has_Shovel_Owns_Shovel;           // 0x0099(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_InteractableList_Explosives_C_Create_Shovel_Items) == 0x000008, "Wrong alignment on W_InteractableList_Explosives_C_Create_Shovel_Items");
static_assert(sizeof(W_InteractableList_Explosives_C_Create_Shovel_Items) == 0x0000A0, "Wrong size on W_InteractableList_Explosives_C_Create_Shovel_Items");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, L_Interact_Data_Array) == 0x000000, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::L_Interact_Data_Array' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, Temp_bool_Variable) == 0x000010, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, CallFunc_Is_Deployable_Built_Is_Built) == 0x000011, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::CallFunc_Is_Deployable_Built_Is_Built' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, CallFunc_Is_Deployable_Built_Full_Health) == 0x000012, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::CallFunc_Is_Deployable_Built_Full_Health' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, K2Node_MakeStruct_FormatArgumentData) == 0x000018, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, K2Node_MakeArray_Array) == 0x000058, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, CallFunc_Format_ReturnValue) == 0x000068, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, K2Node_Select_Default) == 0x000080, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, CallFunc_Soldier_Has_Shovel_Shovel_Equipped) == 0x000098, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::CallFunc_Soldier_Has_Shovel_Shovel_Equipped' has a wrong offset!");
static_assert(offsetof(W_InteractableList_Explosives_C_Create_Shovel_Items, CallFunc_Soldier_Has_Shovel_Owns_Shovel) == 0x000099, "Member 'W_InteractableList_Explosives_C_Create_Shovel_Items::CallFunc_Soldier_Has_Shovel_Owns_Shovel' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Get Interact List
// 0x0008 (0x0008 - 0x0000)
struct W_InteractableList_Explosives_C_Get_Interact_List final
{
public:
	class UVerticalBox*                           Param_InteractList;                                // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Explosives_C_Get_Interact_List) == 0x000008, "Wrong alignment on W_InteractableList_Explosives_C_Get_Interact_List");
static_assert(sizeof(W_InteractableList_Explosives_C_Get_Interact_List) == 0x000008, "Wrong size on W_InteractableList_Explosives_C_Get_Interact_List");
static_assert(offsetof(W_InteractableList_Explosives_C_Get_Interact_List, Param_InteractList) == 0x000000, "Member 'W_InteractableList_Explosives_C_Get_Interact_List::Param_InteractList' has a wrong offset!");

// Function W_InteractableList_Explosives.W_InteractableList_Explosives_C.Get Fade Animation
// 0x0008 (0x0008 - 0x0000)
struct W_InteractableList_Explosives_C_Get_Fade_Animation final
{
public:
	class UWidgetAnimation*                       Fade_Animation;                                    // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_InteractableList_Explosives_C_Get_Fade_Animation) == 0x000008, "Wrong alignment on W_InteractableList_Explosives_C_Get_Fade_Animation");
static_assert(sizeof(W_InteractableList_Explosives_C_Get_Fade_Animation) == 0x000008, "Wrong size on W_InteractableList_Explosives_C_Get_Fade_Animation");
static_assert(offsetof(W_InteractableList_Explosives_C_Get_Fade_Animation, Fade_Animation) == 0x000000, "Member 'W_InteractableList_Explosives_C_Get_Fade_Animation::Fade_Animation' has a wrong offset!");

}

