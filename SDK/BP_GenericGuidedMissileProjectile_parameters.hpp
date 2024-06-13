#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericGuidedMissileProjectile

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_GenericGuidedMissileProjectile.BP_GenericGuidedMissileProjectile_C.ExecuteUbergraph_BP_GenericGuidedMissileProjectile
// 0x00E0 (0x00E0 - 0x0000)
struct BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsDedicatedServer_ReturnValue;            // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B79[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 K2Node_Event_SelfActor;                            // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 K2Node_Event_OtherActor;                           // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                K2Node_Event_NormalImpulse;                        // 0x0018(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             K2Node_Event_Hit;                                  // 0x0024(0x0088)(ConstParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	float                                         CallFunc_GetGameTimeSinceCreation_ReturnValue;     // 0x00AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B7A[0x3];                                     // 0x00B1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x00B4(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B7B[0x7];                                     // 0x00C1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UAudioComponent*                        CallFunc_SpawnSoundAtLocation_ReturnValue;         // 0x00C8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B7C[0x7];                                     // 0x00D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UParticleSystemComponent*               CallFunc_SpawnEmitterAtLocation_ReturnValue;       // 0x00D8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile) == 0x000008, "Wrong alignment on BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile");
static_assert(sizeof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile) == 0x0000E0, "Wrong size on BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, EntryPoint) == 0x000000, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_IsDedicatedServer_ReturnValue) == 0x000004, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_IsDedicatedServer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_Not_PreBool_ReturnValue) == 0x000005, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, K2Node_Event_SelfActor) == 0x000008, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::K2Node_Event_SelfActor' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, K2Node_Event_OtherActor) == 0x000010, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::K2Node_Event_OtherActor' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, K2Node_Event_NormalImpulse) == 0x000018, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::K2Node_Event_NormalImpulse' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, K2Node_Event_Hit) == 0x000024, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::K2Node_Event_Hit' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_GetGameTimeSinceCreation_ReturnValue) == 0x0000AC, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_GetGameTimeSinceCreation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x0000B0, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x0000B4, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_BooleanAND_ReturnValue) == 0x0000C0, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_SpawnSoundAtLocation_ReturnValue) == 0x0000C8, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_SpawnSoundAtLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_IsValid_ReturnValue) == 0x0000D0, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile, CallFunc_SpawnEmitterAtLocation_ReturnValue) == 0x0000D8, "Member 'BP_GenericGuidedMissileProjectile_C_ExecuteUbergraph_BP_GenericGuidedMissileProjectile::CallFunc_SpawnEmitterAtLocation_ReturnValue' has a wrong offset!");

// Function BP_GenericGuidedMissileProjectile.BP_GenericGuidedMissileProjectile_C.OnImpact
// 0x00A8 (0x00A8 - 0x0000)
struct BP_GenericGuidedMissileProjectile_C_OnImpact final
{
public:
	class AActor*                                 SelfActor;                                         // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 OtherActor;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                NormalImpulse;                                     // 0x0010(0x000C)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             Hit;                                               // 0x001C(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(BP_GenericGuidedMissileProjectile_C_OnImpact) == 0x000008, "Wrong alignment on BP_GenericGuidedMissileProjectile_C_OnImpact");
static_assert(sizeof(BP_GenericGuidedMissileProjectile_C_OnImpact) == 0x0000A8, "Wrong size on BP_GenericGuidedMissileProjectile_C_OnImpact");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_OnImpact, SelfActor) == 0x000000, "Member 'BP_GenericGuidedMissileProjectile_C_OnImpact::SelfActor' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_OnImpact, OtherActor) == 0x000008, "Member 'BP_GenericGuidedMissileProjectile_C_OnImpact::OtherActor' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_OnImpact, NormalImpulse) == 0x000010, "Member 'BP_GenericGuidedMissileProjectile_C_OnImpact::NormalImpulse' has a wrong offset!");
static_assert(offsetof(BP_GenericGuidedMissileProjectile_C_OnImpact, Hit) == 0x00001C, "Member 'BP_GenericGuidedMissileProjectile_C_OnImpact::Hit' has a wrong offset!");

}

