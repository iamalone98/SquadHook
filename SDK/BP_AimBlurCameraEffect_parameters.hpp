#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_AimBlurCameraEffect

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_AimBlurCameraEffect.BP_AimBlurCameraEffect_C.ExecuteUbergraph_BP_AimBlurCameraEffect
// 0x0600 (0x0600 - 0x0000)
struct BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F86[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FWeightedBlendable                     K2Node_MakeStruct_WeightedBlendable;               // 0x0008(0x0010)(NoDestructor)
	class ASQPlayerController*                    K2Node_Event_InPlayerController;                   // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F87[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_AddUnique_ReturnValue;              // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F88[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FWeightedBlendables                    K2Node_MakeStruct_WeightedBlendables;              // 0x0038(0x0010)()
	float                                         K2Node_Event_DeltaTime;                            // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F89[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             K2Node_Event_SoldierToApplyTo;                     // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F8A[0x8];                                     // 0x0058(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPostProcessSettings                   K2Node_MakeStruct_PostProcessSettings;             // 0x0060(0x0560)()
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x05C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsInVehicle_ReturnValue;                  // 0x05C1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F8B[0x6];                                     // 0x05C2(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_GetCurrentWeapon_ReturnValue;             // 0x05C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x05D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F8C[0x7];                                     // 0x05D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQWeapon*                              K2Node_DynamicCast_AsSQWeapon;                     // 0x05D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x05E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F8D[0x3];                                     // 0x05E1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x05E4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x05E8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x05E9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F8E[0x2];                                     // 0x05EA(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetFloatValue_ReturnValue;                // 0x05EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_FloatFloat_ReturnValue;           // 0x05F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2F8F[0x3];                                     // 0x05F1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x05F4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x05F8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect) == 0x000010, "Wrong alignment on BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect");
static_assert(sizeof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect) == 0x000600, "Wrong size on BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, EntryPoint) == 0x000000, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_MakeStruct_WeightedBlendable) == 0x000008, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_MakeStruct_WeightedBlendable' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_Event_InPlayerController) == 0x000018, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_Event_InPlayerController' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsValid_ReturnValue) == 0x000020, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000028, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_Array_AddUnique_ReturnValue) == 0x000030, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_Array_AddUnique_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_MakeStruct_WeightedBlendables) == 0x000038, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_MakeStruct_WeightedBlendables' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_Event_DeltaTime) == 0x000048, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_Event_DeltaTime' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_Event_SoldierToApplyTo) == 0x000050, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_Event_SoldierToApplyTo' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_MakeStruct_PostProcessSettings) == 0x000060, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_MakeStruct_PostProcessSettings' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsValid_ReturnValue_1) == 0x0005C0, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsInVehicle_ReturnValue) == 0x0005C1, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsInVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_GetCurrentWeapon_ReturnValue) == 0x0005C8, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_GetCurrentWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_Not_PreBool_ReturnValue) == 0x0005D0, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_DynamicCast_AsSQWeapon) == 0x0005D8, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_DynamicCast_AsSQWeapon' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, K2Node_DynamicCast_bSuccess) == 0x0005E0, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_Conv_IntToFloat_ReturnValue) == 0x0005E4, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsValid_ReturnValue_2) == 0x0005E8, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsValid_ReturnValue_3) == 0x0005E9, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_GetFloatValue_ReturnValue) == 0x0005EC, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_GetFloatValue_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_Greater_FloatFloat_ReturnValue) == 0x0005F0, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_Greater_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0005F4, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect, CallFunc_IsValid_ReturnValue_4) == 0x0005F8, "Member 'BP_AimBlurCameraEffect_C_ExecuteUbergraph_BP_AimBlurCameraEffect::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");

// Function BP_AimBlurCameraEffect.BP_AimBlurCameraEffect_C.BP_InitCameraEffect
// 0x0008 (0x0008 - 0x0000)
struct BP_AimBlurCameraEffect_C_BP_InitCameraEffect final
{
public:
	class ASQPlayerController*                    InPlayerController;                                // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_AimBlurCameraEffect_C_BP_InitCameraEffect) == 0x000008, "Wrong alignment on BP_AimBlurCameraEffect_C_BP_InitCameraEffect");
static_assert(sizeof(BP_AimBlurCameraEffect_C_BP_InitCameraEffect) == 0x000008, "Wrong size on BP_AimBlurCameraEffect_C_BP_InitCameraEffect");
static_assert(offsetof(BP_AimBlurCameraEffect_C_BP_InitCameraEffect, InPlayerController) == 0x000000, "Member 'BP_AimBlurCameraEffect_C_BP_InitCameraEffect::InPlayerController' has a wrong offset!");

// Function BP_AimBlurCameraEffect.BP_AimBlurCameraEffect_C.BP_ApplyCameraEffect
// 0x0010 (0x0010 - 0x0000)
struct BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect final
{
public:
	float                                         DeltaTime;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F90[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             SoldierToApplyTo;                                  // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect) == 0x000008, "Wrong alignment on BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect");
static_assert(sizeof(BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect) == 0x000010, "Wrong size on BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect");
static_assert(offsetof(BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect, DeltaTime) == 0x000000, "Member 'BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect::DeltaTime' has a wrong offset!");
static_assert(offsetof(BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect, SoldierToApplyTo) == 0x000008, "Member 'BP_AimBlurCameraEffect_C_BP_ApplyCameraEffect::SoldierToApplyTo' has a wrong offset!");

}
