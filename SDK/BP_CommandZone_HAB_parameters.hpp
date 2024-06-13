#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CommandZone_HAB

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BP_CommandZone_HAB.BP_CommandZone_HAB_C.ExecuteUbergraph_BP_CommandZone_HAB
// 0x0018 (0x0018 - 0x0000)
struct BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F4C[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_Get_Overlapping_Commander_AsSQPlayer_Controller; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB) == 0x000008, "Wrong alignment on BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB");
static_assert(sizeof(BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB) == 0x000018, "Wrong size on BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB");
static_assert(offsetof(BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB, EntryPoint) == 0x000000, "Member 'BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB, CallFunc_Get_Overlapping_Commander_AsSQPlayer_Controller) == 0x000008, "Member 'BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB::CallFunc_Get_Overlapping_Commander_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'BP_CommandZone_HAB_C_ExecuteUbergraph_BP_CommandZone_HAB::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function BP_CommandZone_HAB.BP_CommandZone_HAB_C.Can Allow Actions
// 0x0028 (0x0028 - 0x0000)
struct BP_CommandZone_HAB_C_Can_Allow_Actions final
{
public:
	bool                                          Allow_Actions;                                     // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F4D[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetParentActor_ReturnValue;               // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Can_Allow_Actions_Allow_Actions;          // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4F4E[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_Deployable_Hab_C*                   K2Node_DynamicCast_AsBP_Deployable_Hab;            // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESQBuildState                                 CallFunc_GetBuildState_ReturnValue;                // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0022(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0023(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_1;                 // 0x0025(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_CommandZone_HAB_C_Can_Allow_Actions) == 0x000008, "Wrong alignment on BP_CommandZone_HAB_C_Can_Allow_Actions");
static_assert(sizeof(BP_CommandZone_HAB_C_Can_Allow_Actions) == 0x000028, "Wrong size on BP_CommandZone_HAB_C_Can_Allow_Actions");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, Allow_Actions) == 0x000000, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::Allow_Actions' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_GetParentActor_ReturnValue) == 0x000008, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_GetParentActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_Can_Allow_Actions_Allow_Actions) == 0x000010, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_Can_Allow_Actions_Allow_Actions' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, K2Node_DynamicCast_AsBP_Deployable_Hab) == 0x000018, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::K2Node_DynamicCast_AsBP_Deployable_Hab' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_GetBuildState_ReturnValue) == 0x000021, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_GetBuildState_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_Not_PreBool_ReturnValue) == 0x000022, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000023, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_BooleanAND_ReturnValue) == 0x000024, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommandZone_HAB_C_Can_Allow_Actions, CallFunc_BooleanAND_ReturnValue_1) == 0x000025, "Member 'BP_CommandZone_HAB_C_Can_Allow_Actions::CallFunc_BooleanAND_ReturnValue_1' has a wrong offset!");

}

