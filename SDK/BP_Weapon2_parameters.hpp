#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Weapon2

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_Weapon2.BP_Weapon2_C.ExecuteUbergraph_BP_Weapon2
// 0x00F8 (0x00F8 - 0x0000)
struct BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2 final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39AE[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             CallFunc_GetOwnerSoldier_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_MutableSoldier_C*                   K2Node_DynamicCast_AsBP_Mutable_Soldier;           // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsLocallyControlled_ReturnValue;          // 0x0019(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39AF[0x2];                                     // 0x001A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                K2Node_Event_Origin;                               // 0x001C(0x000C)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerCameraManager*                   CallFunc_GetPlayerCameraManager_ReturnValue;       // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue;         // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FInterpTo_ReturnValue;                    // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Event_DeltaSeconds;                         // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsPlayingInEditor_ReturnValue;            // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B0[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 K2Node_CustomEvent_CVarName;                       // 0x0040(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetConsoleVariableBoolValue_ReturnValue;  // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_StrStr_ReturnValue;            // 0x0051(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B1[0x6];                                     // 0x0052(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue;          // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_GetControlRotation_ReturnValue;           // 0x0060(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsPlayingInEditor_ReturnValue_1;          // 0x006C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B2[0x3];                                     // 0x006D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0078(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x007C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	class USQWeaponStaticInfo*                    CallFunc_GetWeaponStaticInfo_ReturnValue;          // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void(const class FString& CVarName)> K2Node_CreateDelegate_OutputDelegate;              // 0x0090(0x0010)(ZeroConstructor, NoDestructor)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39B3[0x4];                                     // 0x00A4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UCameraShakeBase*                       CallFunc_StartCameraShake_ReturnValue;             // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_FloatFloat_ReturnValue;              // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B4[0x3];                                     // 0x00B1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_SelectFloat_ReturnValue;                  // 0x00B4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00B8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B5[0x3];                                     // 0x00B9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCameraShakeBase*                       CallFunc_StartCameraShake_ReturnValue_1;           // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_GetDisplayName_ReturnValue;               // 0x00C8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class UDataDrivenCVarEngineSubsystem*         CallFunc_GetEngineSubsystem_ReturnValue;           // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Concat_StrStr_ReturnValue;                // 0x00E0(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsPlayingInEditor_ReturnValue_2;          // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2) == 0x000008, "Wrong alignment on BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2");
static_assert(sizeof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2) == 0x0000F8, "Wrong size on BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, EntryPoint) == 0x000000, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetOwnerSoldier_ReturnValue) == 0x000008, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetOwnerSoldier_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_DynamicCast_AsBP_Mutable_Soldier) == 0x000010, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_DynamicCast_AsBP_Mutable_Soldier' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_IsLocallyControlled_ReturnValue) == 0x000019, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_IsLocallyControlled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_Event_Origin) == 0x00001C, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_Event_Origin' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetPlayerCameraManager_ReturnValue) == 0x000028, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetPlayerCameraManager_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetWorldDeltaSeconds_ReturnValue) == 0x000030, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetWorldDeltaSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_FInterpTo_ReturnValue) == 0x000034, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_FInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_Event_DeltaSeconds) == 0x000038, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_IsPlayingInEditor_ReturnValue) == 0x00003C, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_IsPlayingInEditor_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_CustomEvent_CVarName) == 0x000040, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_CustomEvent_CVarName' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetConsoleVariableBoolValue_ReturnValue) == 0x000050, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetConsoleVariableBoolValue_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_EqualEqual_StrStr_ReturnValue) == 0x000051, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_EqualEqual_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetPlayerController_ReturnValue) == 0x000058, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetControlRotation_ReturnValue) == 0x000060, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetControlRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_IsPlayingInEditor_ReturnValue_1) == 0x00006C, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_IsPlayingInEditor_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_BreakRotator_Roll) == 0x000070, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_BreakRotator_Pitch) == 0x000074, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_BreakRotator_Yaw) == 0x000078, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_MakeRotator_ReturnValue) == 0x00007C, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetWeaponStaticInfo_ReturnValue) == 0x000088, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetWeaponStaticInfo_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, K2Node_CreateDelegate_OutputDelegate) == 0x000090, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000A0, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_StartCameraShake_ReturnValue) == 0x0000A8, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_StartCameraShake_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_Less_FloatFloat_ReturnValue) == 0x0000B0, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_Less_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_SelectFloat_ReturnValue) == 0x0000B4, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_SelectFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_IsValid_ReturnValue) == 0x0000B8, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0000BC, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_StartCameraShake_ReturnValue_1) == 0x0000C0, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_StartCameraShake_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetDisplayName_ReturnValue) == 0x0000C8, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetDisplayName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_GetEngineSubsystem_ReturnValue) == 0x0000D8, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_GetEngineSubsystem_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_Concat_StrStr_ReturnValue) == 0x0000E0, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_Concat_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2, CallFunc_IsPlayingInEditor_ReturnValue_2) == 0x0000F0, "Member 'BP_Weapon2_C_ExecuteUbergraph_BP_Weapon2::CallFunc_IsPlayingInEditor_ReturnValue_2' has a wrong offset!");

// Function BP_Weapon2.BP_Weapon2_C.DebugCvarUpdated
// 0x0010 (0x0010 - 0x0000)
struct BP_Weapon2_C_DebugCvarUpdated final
{
public:
	class FString                                 CVarName;                                          // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Weapon2_C_DebugCvarUpdated) == 0x000008, "Wrong alignment on BP_Weapon2_C_DebugCvarUpdated");
static_assert(sizeof(BP_Weapon2_C_DebugCvarUpdated) == 0x000010, "Wrong size on BP_Weapon2_C_DebugCvarUpdated");
static_assert(offsetof(BP_Weapon2_C_DebugCvarUpdated, CVarName) == 0x000000, "Member 'BP_Weapon2_C_DebugCvarUpdated::CVarName' has a wrong offset!");

// Function BP_Weapon2.BP_Weapon2_C.BlueprintOnFire
// 0x000C (0x000C - 0x0000)
struct BP_Weapon2_C_BlueprintOnFire final
{
public:
	struct FVector                                Origin;                                            // 0x0000(0x000C)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Weapon2_C_BlueprintOnFire) == 0x000004, "Wrong alignment on BP_Weapon2_C_BlueprintOnFire");
static_assert(sizeof(BP_Weapon2_C_BlueprintOnFire) == 0x00000C, "Wrong size on BP_Weapon2_C_BlueprintOnFire");
static_assert(offsetof(BP_Weapon2_C_BlueprintOnFire, Origin) == 0x000000, "Member 'BP_Weapon2_C_BlueprintOnFire::Origin' has a wrong offset!");

// Function BP_Weapon2.BP_Weapon2_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct BP_Weapon2_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Weapon2_C_ReceiveTick) == 0x000004, "Wrong alignment on BP_Weapon2_C_ReceiveTick");
static_assert(sizeof(BP_Weapon2_C_ReceiveTick) == 0x000004, "Wrong size on BP_Weapon2_C_ReceiveTick");
static_assert(offsetof(BP_Weapon2_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'BP_Weapon2_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function BP_Weapon2.BP_Weapon2_C.PrintSocketDebug
// 0x0080 (0x0080 - 0x0000)
struct BP_Weapon2_C_PrintSocketDebug final
{
public:
	struct FVector                                BarrelSocketLocation;                              // 0x0000(0x000C)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               BarrelSocketRotation;                              // 0x000C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         SocketHeightAboveGround;                           // 0x0018(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SoldierFeetZ;                                      // 0x001C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             OwningSoldier;                                     // 0x0020(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsEquipped_ReturnValue;                   // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B6[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x002C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetActorHalfHeight_ReturnValue;           // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X;                            // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             CallFunc_GetOwnerSoldier_ReturnValue;              // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_1;                          // 0x0054(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_1;                          // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_1;                          // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsLocallyControlled_ReturnValue;          // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0062(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39B7[0x1];                                     // 0x0063(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_1;        // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_GetSocketRotation_ReturnValue;            // 0x0068(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector                                CallFunc_GetSocketLocation_ReturnValue;            // 0x0074(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Weapon2_C_PrintSocketDebug) == 0x000008, "Wrong alignment on BP_Weapon2_C_PrintSocketDebug");
static_assert(sizeof(BP_Weapon2_C_PrintSocketDebug) == 0x000080, "Wrong size on BP_Weapon2_C_PrintSocketDebug");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, BarrelSocketLocation) == 0x000000, "Member 'BP_Weapon2_C_PrintSocketDebug::BarrelSocketLocation' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, BarrelSocketRotation) == 0x00000C, "Member 'BP_Weapon2_C_PrintSocketDebug::BarrelSocketRotation' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, SocketHeightAboveGround) == 0x000018, "Member 'BP_Weapon2_C_PrintSocketDebug::SocketHeightAboveGround' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, SoldierFeetZ) == 0x00001C, "Member 'BP_Weapon2_C_PrintSocketDebug::SoldierFeetZ' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, OwningSoldier) == 0x000020, "Member 'BP_Weapon2_C_PrintSocketDebug::OwningSoldier' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_IsEquipped_ReturnValue) == 0x000028, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_IsEquipped_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_K2_GetActorLocation_ReturnValue) == 0x00002C, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_GetActorHalfHeight_ReturnValue) == 0x000038, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_GetActorHalfHeight_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_X) == 0x00003C, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_Y) == 0x000040, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_Z) == 0x000044, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_GetOwnerSoldier_ReturnValue) == 0x000048, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_GetOwnerSoldier_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000050, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_X_1) == 0x000054, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_X_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_Y_1) == 0x000058, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_Y_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BreakVector_Z_1) == 0x00005C, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BreakVector_Z_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_IsLocallyControlled_ReturnValue) == 0x000060, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_IsLocallyControlled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_IsValid_ReturnValue) == 0x000061, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_BooleanAND_ReturnValue) == 0x000062, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_Subtract_FloatFloat_ReturnValue_1) == 0x000064, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_Subtract_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_GetSocketRotation_ReturnValue) == 0x000068, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_GetSocketRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Weapon2_C_PrintSocketDebug, CallFunc_GetSocketLocation_ReturnValue) == 0x000074, "Member 'BP_Weapon2_C_PrintSocketDebug::CallFunc_GetSocketLocation_ReturnValue' has a wrong offset!");

}

