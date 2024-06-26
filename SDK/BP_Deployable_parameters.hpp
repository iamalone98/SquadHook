#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Deployable

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_Deployable.BP_Deployable_C.ExecuteUbergraph_BP_Deployable
// 0x00D0 (0x00D0 - 0x0000)
struct BP_Deployable_C_ExecuteUbergraph_BP_Deployable final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x0004(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class AActor*>                         Temp_object_Variable;                              // 0x0010(0x0010)(ConstParm, ReferenceParm)
	float                                         K2Node_Event_DeltaSeconds;                         // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsGhost_ReturnValue;                      // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1BF0[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_MakeVector_ReturnValue;                   // 0x0028(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_FloatFloat_ReturnValue;           // 0x0034(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1BF1[0x3];                                     // 0x0035(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_Add_VectorVector_ReturnValue;             // 0x0038(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             CallFunc_LineTraceSingle_OutHit;                   // 0x0044(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          CallFunc_LineTraceSingle_ReturnValue;              // 0x00CC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable) == 0x000008, "Wrong alignment on BP_Deployable_C_ExecuteUbergraph_BP_Deployable");
static_assert(sizeof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable) == 0x0000D0, "Wrong size on BP_Deployable_C_ExecuteUbergraph_BP_Deployable");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, EntryPoint) == 0x000000, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_K2_GetActorLocation_ReturnValue) == 0x000004, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, Temp_object_Variable) == 0x000010, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::Temp_object_Variable' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, K2Node_Event_DeltaSeconds) == 0x000020, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_IsGhost_ReturnValue) == 0x000024, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_IsGhost_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_MakeVector_ReturnValue) == 0x000028, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_MakeVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_Greater_FloatFloat_ReturnValue) == 0x000034, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_Greater_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_Add_VectorVector_ReturnValue) == 0x000038, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_Add_VectorVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_LineTraceSingle_OutHit) == 0x000044, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_LineTraceSingle_OutHit' has a wrong offset!");
static_assert(offsetof(BP_Deployable_C_ExecuteUbergraph_BP_Deployable, CallFunc_LineTraceSingle_ReturnValue) == 0x0000CC, "Member 'BP_Deployable_C_ExecuteUbergraph_BP_Deployable::CallFunc_LineTraceSingle_ReturnValue' has a wrong offset!");

// Function BP_Deployable.BP_Deployable_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct BP_Deployable_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Deployable_C_ReceiveTick) == 0x000004, "Wrong alignment on BP_Deployable_C_ReceiveTick");
static_assert(sizeof(BP_Deployable_C_ReceiveTick) == 0x000004, "Wrong size on BP_Deployable_C_ReceiveTick");
static_assert(offsetof(BP_Deployable_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'BP_Deployable_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

}

