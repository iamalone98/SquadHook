#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ocean_Squad

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_Ocean_Squad.BP_Ocean_Squad_C.ExecuteUbergraph_BP_Ocean_Squad
// 0x00A8 (0x00A8 - 0x0000)
struct BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_40E2[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0018(0x0008)(NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Event_DeltaSeconds;                         // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40E3[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_TryGetLocalPlayerController_OutPlayerController; // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetLocalPlayerController_ReturnValue;  // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40E4[0x3];                                     // 0x0031(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_GetCameraLocation_ReturnValue;            // 0x0034(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X;                            // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x004C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_1;                          // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_1;                          // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_1;                          // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_2;                          // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_2;                          // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_2;                          // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_MakeVector_ReturnValue;                   // 0x0070(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_MakeVector_ReturnValue_1;                 // 0x007C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x0088(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsShippingBuild_ReturnValue;              // 0x0094(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40E5[0x3];                                     // 0x0095(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakVector_X_3;                          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_3;                          // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_3;                          // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad) == 0x000008, "Wrong alignment on BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad");
static_assert(sizeof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad) == 0x0000A8, "Wrong size on BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, EntryPoint) == 0x000000, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000018, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, K2Node_Event_DeltaSeconds) == 0x000020, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_TryGetLocalPlayerController_OutPlayerController) == 0x000028, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_TryGetLocalPlayerController_OutPlayerController' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_TryGetLocalPlayerController_ReturnValue) == 0x000030, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_TryGetLocalPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_GetCameraLocation_ReturnValue) == 0x000034, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_GetCameraLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_X) == 0x000040, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Y) == 0x000044, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Z) == 0x000048, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x00004C, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_X_1) == 0x000058, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_X_1' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Y_1) == 0x00005C, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Y_1' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Z_1) == 0x000060, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Z_1' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_X_2) == 0x000064, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_X_2' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Y_2) == 0x000068, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Y_2' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Z_2) == 0x00006C, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Z_2' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_MakeVector_ReturnValue) == 0x000070, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_MakeVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_MakeVector_ReturnValue_1) == 0x00007C, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_MakeVector_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_K2_GetActorLocation_ReturnValue) == 0x000088, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_IsShippingBuild_ReturnValue) == 0x000094, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_IsShippingBuild_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_X_3) == 0x000098, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_X_3' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Y_3) == 0x00009C, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Y_3' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_BreakVector_Z_3) == 0x0000A0, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_BreakVector_Z_3' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x0000A4, "Member 'BP_Ocean_Squad_C_ExecuteUbergraph_BP_Ocean_Squad::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_Ocean_Squad.BP_Ocean_Squad_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct BP_Ocean_Squad_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Ocean_Squad_C_ReceiveTick) == 0x000004, "Wrong alignment on BP_Ocean_Squad_C_ReceiveTick");
static_assert(sizeof(BP_Ocean_Squad_C_ReceiveTick) == 0x000004, "Wrong size on BP_Ocean_Squad_C_ReceiveTick");
static_assert(offsetof(BP_Ocean_Squad_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'BP_Ocean_Squad_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function BP_Ocean_Squad.BP_Ocean_Squad_C.GetActorImmersionDepth
// 0x0010 (0x0010 - 0x0000)
struct BP_Ocean_Squad_C_GetActorImmersionDepth final
{
public:
	const class AActor*                           QueryingActor;                                     // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ReturnValue;                                       // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetActorImmersionDepthInWater_ReturnValue; // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Ocean_Squad_C_GetActorImmersionDepth) == 0x000008, "Wrong alignment on BP_Ocean_Squad_C_GetActorImmersionDepth");
static_assert(sizeof(BP_Ocean_Squad_C_GetActorImmersionDepth) == 0x000010, "Wrong size on BP_Ocean_Squad_C_GetActorImmersionDepth");
static_assert(offsetof(BP_Ocean_Squad_C_GetActorImmersionDepth, QueryingActor) == 0x000000, "Member 'BP_Ocean_Squad_C_GetActorImmersionDepth::QueryingActor' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_GetActorImmersionDepth, ReturnValue) == 0x000008, "Member 'BP_Ocean_Squad_C_GetActorImmersionDepth::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_GetActorImmersionDepth, CallFunc_GetActorImmersionDepthInWater_ReturnValue) == 0x00000C, "Member 'BP_Ocean_Squad_C_GetActorImmersionDepth::CallFunc_GetActorImmersionDepthInWater_ReturnValue' has a wrong offset!");

// Function BP_Ocean_Squad.BP_Ocean_Squad_C.HasValidProjectileOverlap
// 0x00B0 (0x00B0 - 0x0000)
struct BP_Ocean_Squad_C_HasValidProjectileOverlap final
{
public:
	class UPrimitiveComponent*                    OverlappedComponent;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 OtherActor;                                        // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPrimitiveComponent*                    OtherComp;                                         // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         OtherBodyIndex;                                    // 0x0018(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bFromSweep;                                        // 0x001C(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40E6[0x3];                                     // 0x001D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FHitResult                             SweepResult;                                       // 0x0020(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          ReturnValue;                                       // 0x00A8(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_WaterHasValidOverlap_ReturnValue;         // 0x00A9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Ocean_Squad_C_HasValidProjectileOverlap) == 0x000008, "Wrong alignment on BP_Ocean_Squad_C_HasValidProjectileOverlap");
static_assert(sizeof(BP_Ocean_Squad_C_HasValidProjectileOverlap) == 0x0000B0, "Wrong size on BP_Ocean_Squad_C_HasValidProjectileOverlap");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, OverlappedComponent) == 0x000000, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::OverlappedComponent' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, OtherActor) == 0x000008, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::OtherActor' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, OtherComp) == 0x000010, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::OtherComp' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, OtherBodyIndex) == 0x000018, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::OtherBodyIndex' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, bFromSweep) == 0x00001C, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::bFromSweep' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, SweepResult) == 0x000020, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::SweepResult' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, ReturnValue) == 0x0000A8, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileOverlap, CallFunc_WaterHasValidOverlap_ReturnValue) == 0x0000A9, "Member 'BP_Ocean_Squad_C_HasValidProjectileOverlap::CallFunc_WaterHasValidOverlap_ReturnValue' has a wrong offset!");

// Function BP_Ocean_Squad.BP_Ocean_Squad_C.HasValidProjectileHit
// 0x0098 (0x0098 - 0x0000)
struct BP_Ocean_Squad_C_HasValidProjectileHit final
{
public:
	const class AActor*                           ProjectileOwner;                                   // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             InHit;                                             // 0x0008(0x0088)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          ReturnValue;                                       // 0x0090(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_WaterHasValidHit_ReturnValue;             // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Ocean_Squad_C_HasValidProjectileHit) == 0x000008, "Wrong alignment on BP_Ocean_Squad_C_HasValidProjectileHit");
static_assert(sizeof(BP_Ocean_Squad_C_HasValidProjectileHit) == 0x000098, "Wrong size on BP_Ocean_Squad_C_HasValidProjectileHit");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileHit, ProjectileOwner) == 0x000000, "Member 'BP_Ocean_Squad_C_HasValidProjectileHit::ProjectileOwner' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileHit, InHit) == 0x000008, "Member 'BP_Ocean_Squad_C_HasValidProjectileHit::InHit' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileHit, ReturnValue) == 0x000090, "Member 'BP_Ocean_Squad_C_HasValidProjectileHit::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Ocean_Squad_C_HasValidProjectileHit, CallFunc_WaterHasValidHit_ReturnValue) == 0x000091, "Member 'BP_Ocean_Squad_C_HasValidProjectileHit::CallFunc_WaterHasValidHit_ReturnValue' has a wrong offset!");

}
