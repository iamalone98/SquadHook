#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_S5_Proj2

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_S5_Proj2.BP_S5_Proj2_C.ExecuteUbergraph_BP_S5_Proj2
// 0x00D8 (0x00D8 - 0x0000)
struct BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2 final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsDedicatedServer_ReturnValue;            // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36DE[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 K2Node_Event_SelfActor;                            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 K2Node_Event_OtherActor;                           // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                K2Node_Event_NormalImpulse;                        // 0x0018(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             K2Node_Event_Hit;                                  // 0x0024(0x0088)(ConstParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x00AC(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetGameTimeSinceCreation_ReturnValue;     // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_36DF[0x4];                                     // 0x00BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAudioComponent*                        CallFunc_SpawnSoundAtLocation_ReturnValue;         // 0x00C0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               CallFunc_SpawnEmitterAtLocation_ReturnValue;       // 0x00C8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x00D1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00D2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2) == 0x000008, "Wrong alignment on BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2");
static_assert(sizeof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2) == 0x0000D8, "Wrong size on BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, EntryPoint) == 0x000000, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_IsDedicatedServer_ReturnValue) == 0x000004, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_IsDedicatedServer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_Not_PreBool_ReturnValue) == 0x000005, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, K2Node_Event_SelfActor) == 0x000008, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::K2Node_Event_SelfActor' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, K2Node_Event_OtherActor) == 0x000010, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::K2Node_Event_OtherActor' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, K2Node_Event_NormalImpulse) == 0x000018, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::K2Node_Event_NormalImpulse' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, K2Node_Event_Hit) == 0x000024, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::K2Node_Event_Hit' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x0000AC, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_GetGameTimeSinceCreation_ReturnValue) == 0x0000B8, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_GetGameTimeSinceCreation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_SpawnSoundAtLocation_ReturnValue) == 0x0000C0, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_SpawnSoundAtLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_SpawnEmitterAtLocation_ReturnValue) == 0x0000C8, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_SpawnEmitterAtLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_IsValid_ReturnValue) == 0x0000D0, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x0000D1, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2, CallFunc_BooleanAND_ReturnValue) == 0x0000D2, "Member 'BP_S5_Proj2_C_ExecuteUbergraph_BP_S5_Proj2::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function BP_S5_Proj2.BP_S5_Proj2_C.OnImpact
// 0x00A8 (0x00A8 - 0x0000)
struct BP_S5_Proj2_C_OnImpact final
{
public:
	class AActor*                                 SelfActor;                                         // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 OtherActor;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                NormalImpulse;                                     // 0x0010(0x000C)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             Hit;                                               // 0x001C(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(BP_S5_Proj2_C_OnImpact) == 0x000008, "Wrong alignment on BP_S5_Proj2_C_OnImpact");
static_assert(sizeof(BP_S5_Proj2_C_OnImpact) == 0x0000A8, "Wrong size on BP_S5_Proj2_C_OnImpact");
static_assert(offsetof(BP_S5_Proj2_C_OnImpact, SelfActor) == 0x000000, "Member 'BP_S5_Proj2_C_OnImpact::SelfActor' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_OnImpact, OtherActor) == 0x000008, "Member 'BP_S5_Proj2_C_OnImpact::OtherActor' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_OnImpact, NormalImpulse) == 0x000010, "Member 'BP_S5_Proj2_C_OnImpact::NormalImpulse' has a wrong offset!");
static_assert(offsetof(BP_S5_Proj2_C_OnImpact, Hit) == 0x00001C, "Member 'BP_S5_Proj2_C_OnImpact::Hit' has a wrong offset!");

}

