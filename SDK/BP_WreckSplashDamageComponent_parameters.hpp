#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_WreckSplashDamageComponent

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_WreckSplashDamageComponent.BP_WreckSplashDamageComponent_C.ExecuteUbergraph_BP_WreckSplashDamageComponent
// 0x0188 (0x0188 - 0x0000)
struct BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2E0C[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQDestroyedVehicle*                    K2Node_DynamicCast_AsSQDestroyed_Vehicle;          // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E0D[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 CallFunc_GetObjectClass_ReturnValue;               // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_GetClassDisplayName_ReturnValue;          // 0x0020(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetComponentBounds_Origin;                // 0x0030(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetComponentBounds_BoxExtent;             // 0x003C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetComponentBounds_SphereRadius;          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2E0E[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0050(0x0018)()
	struct FHitResult                             CallFunc_K2_SetWorldLocation_SweepHitResult;       // 0x0068(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x00F0(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0130(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0140(0x0018)()
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0158(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E0F[0x7];                                     // 0x0159(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class AActor*>                         K2Node_MakeArray_Array_1;                          // 0x0160(0x0010)(ConstParm, ReferenceParm)
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0170(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x0178(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_ApplyRadialDamageWithFalloff_ReturnValue; // 0x0184(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0185(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasAuthority_ReturnValue_1;               // 0x0186(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent) == 0x000008, "Wrong alignment on BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent");
static_assert(sizeof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent) == 0x000188, "Wrong size on BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, EntryPoint) == 0x000000, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, K2Node_DynamicCast_AsSQDestroyed_Vehicle) == 0x000008, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::K2Node_DynamicCast_AsSQDestroyed_Vehicle' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetObjectClass_ReturnValue) == 0x000018, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetObjectClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetClassDisplayName_ReturnValue) == 0x000020, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetClassDisplayName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetComponentBounds_Origin) == 0x000030, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetComponentBounds_Origin' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetComponentBounds_BoxExtent) == 0x00003C, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetComponentBounds_BoxExtent' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetComponentBounds_SphereRadius) == 0x000048, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetComponentBounds_SphereRadius' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_Conv_StringToText_ReturnValue) == 0x000050, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_K2_SetWorldLocation_SweepHitResult) == 0x000068, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_K2_SetWorldLocation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, K2Node_MakeStruct_FormatArgumentData) == 0x0000F0, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, K2Node_MakeArray_Array) == 0x000130, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_Format_ReturnValue) == 0x000140, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_HasAuthority_ReturnValue) == 0x000158, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, K2Node_MakeArray_Array_1) == 0x000160, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_GetOwner_ReturnValue) == 0x000170, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x000178, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_ApplyRadialDamageWithFalloff_ReturnValue) == 0x000184, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_ApplyRadialDamageWithFalloff_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_IsValid_ReturnValue) == 0x000185, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent, CallFunc_HasAuthority_ReturnValue_1) == 0x000186, "Member 'BP_WreckSplashDamageComponent_C_ExecuteUbergraph_BP_WreckSplashDamageComponent::CallFunc_HasAuthority_ReturnValue_1' has a wrong offset!");

}
