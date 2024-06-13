#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MagicLeapARPinInfoActor

#include "Basic.hpp"

#include "MagicLeapARPin_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function MagicLeapARPinInfoActor.MagicLeapARPinInfoActor_C.ExecuteUbergraph_MagicLeapARPinInfoActor
// 0x02D8 (0x02D8 - 0x0000)
struct MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2D9B[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerCameraManager*                   CallFunc_GetPlayerCameraManager_ReturnValue;       // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetCameraLocation_ReturnValue;            // 0x0010(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_K2_GetComponentRotation_ReturnValue;      // 0x001C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector                                CallFunc_K2_GetComponentLocation_ReturnValue;      // 0x0028(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_FindLookAtRotation_ReturnValue;           // 0x0034(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector                                CallFunc_GetARPinPositionAndOrientation_Position;  // 0x0040(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_GetARPinPositionAndOrientation_Orientation; // 0x004C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GetARPinPositionAndOrientation_PinFoundInEnvironment; // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GetARPinPositionAndOrientation_ReturnValue; // 0x0059(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D9C[0x2];                                     // 0x005A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FHitResult                             CallFunc_K2_SetWorldLocationAndRotation_SweepHitResult; // 0x005C(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	struct FHitResult                             CallFunc_K2_SetWorldLocation_SweepHitResult;       // 0x00E4(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	float                                         K2Node_Event_DeltaSeconds;                         // 0x016C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_RInterpTo_ReturnValue;                    // 0x0170(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D9D[0x4];                                     // 0x017C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_ARPinIdToString_ReturnValue;              // 0x0180(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0190(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x0194(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0198(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2D9E[0x4];                                     // 0x019C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x01A0(0x0018)()
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x01B8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FHitResult                             CallFunc_K2_SetWorldRotation_SweepHitResult;       // 0x01C4(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	struct FMagicLeapARPinState                   CallFunc_GetARPinState_State;                      // 0x024C(0x0014)(NoDestructor)
	EMagicLeapPassableWorldError                  CallFunc_GetARPinState_ReturnValue;                // 0x0260(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x0261(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D9F[0x6];                                     // 0x0262(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_GetEnumeratorUserFriendlyName_ReturnValue; // 0x0268(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0278(0x0018)()
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_1;          // 0x0290(0x0018)()
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue_1;           // 0x02A8(0x0018)()
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue_2;           // 0x02C0(0x0018)()
};
static_assert(alignof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor) == 0x000008, "Wrong alignment on MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor");
static_assert(sizeof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor) == 0x0002D8, "Wrong size on MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, EntryPoint) == 0x000000, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::EntryPoint' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetPlayerCameraManager_ReturnValue) == 0x000008, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetPlayerCameraManager_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetCameraLocation_ReturnValue) == 0x000010, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetCameraLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_K2_GetComponentRotation_ReturnValue) == 0x00001C, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_K2_GetComponentRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_K2_GetComponentLocation_ReturnValue) == 0x000028, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_K2_GetComponentLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_FindLookAtRotation_ReturnValue) == 0x000034, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_FindLookAtRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinPositionAndOrientation_Position) == 0x000040, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinPositionAndOrientation_Position' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinPositionAndOrientation_Orientation) == 0x00004C, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinPositionAndOrientation_Orientation' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinPositionAndOrientation_PinFoundInEnvironment) == 0x000058, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinPositionAndOrientation_PinFoundInEnvironment' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinPositionAndOrientation_ReturnValue) == 0x000059, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinPositionAndOrientation_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_K2_SetWorldLocationAndRotation_SweepHitResult) == 0x00005C, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_K2_SetWorldLocationAndRotation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_K2_SetWorldLocation_SweepHitResult) == 0x0000E4, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_K2_SetWorldLocation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, K2Node_Event_DeltaSeconds) == 0x00016C, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::K2Node_Event_DeltaSeconds' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_RInterpTo_ReturnValue) == 0x000170, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_RInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_ARPinIdToString_ReturnValue) == 0x000180, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_ARPinIdToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_BreakRotator_Roll) == 0x000190, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_BreakRotator_Pitch) == 0x000194, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_BreakRotator_Yaw) == 0x000198, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_Conv_StringToText_ReturnValue) == 0x0001A0, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_MakeRotator_ReturnValue) == 0x0001B8, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_K2_SetWorldRotation_SweepHitResult) == 0x0001C4, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_K2_SetWorldRotation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinState_State) == 0x00024C, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinState_State' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetARPinState_ReturnValue) == 0x000260, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetARPinState_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x000261, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_GetEnumeratorUserFriendlyName_ReturnValue) == 0x000268, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_GetEnumeratorUserFriendlyName_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_Conv_FloatToText_ReturnValue) == 0x000278, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_Conv_StringToText_ReturnValue_1) == 0x000290, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_Conv_StringToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_Conv_FloatToText_ReturnValue_1) == 0x0002A8, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_Conv_FloatToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor, CallFunc_Conv_FloatToText_ReturnValue_2) == 0x0002C0, "Member 'MagicLeapARPinInfoActor_C_ExecuteUbergraph_MagicLeapARPinInfoActor::CallFunc_Conv_FloatToText_ReturnValue_2' has a wrong offset!");

// Function MagicLeapARPinInfoActor.MagicLeapARPinInfoActor_C.ReceiveTick
// 0x0004 (0x0004 - 0x0000)
struct MagicLeapARPinInfoActor_C_ReceiveTick final
{
public:
	float                                         DeltaSeconds;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(MagicLeapARPinInfoActor_C_ReceiveTick) == 0x000004, "Wrong alignment on MagicLeapARPinInfoActor_C_ReceiveTick");
static_assert(sizeof(MagicLeapARPinInfoActor_C_ReceiveTick) == 0x000004, "Wrong size on MagicLeapARPinInfoActor_C_ReceiveTick");
static_assert(offsetof(MagicLeapARPinInfoActor_C_ReceiveTick, DeltaSeconds) == 0x000000, "Member 'MagicLeapARPinInfoActor_C_ReceiveTick::DeltaSeconds' has a wrong offset!");

// Function MagicLeapARPinInfoActor.MagicLeapARPinInfoActor_C.UserConstructionScript
// 0x0018 (0x0018 - 0x0000)
struct MagicLeapARPinInfoActor_C_UserConstructionScript final
{
public:
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue_1; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue_2; // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(MagicLeapARPinInfoActor_C_UserConstructionScript) == 0x000008, "Wrong alignment on MagicLeapARPinInfoActor_C_UserConstructionScript");
static_assert(sizeof(MagicLeapARPinInfoActor_C_UserConstructionScript) == 0x000018, "Wrong size on MagicLeapARPinInfoActor_C_UserConstructionScript");
static_assert(offsetof(MagicLeapARPinInfoActor_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000000, "Member 'MagicLeapARPinInfoActor_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue_1) == 0x000008, "Member 'MagicLeapARPinInfoActor_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(MagicLeapARPinInfoActor_C_UserConstructionScript, CallFunc_CreateDynamicMaterialInstance_ReturnValue_2) == 0x000010, "Member 'MagicLeapARPinInfoActor_C_UserConstructionScript::CallFunc_CreateDynamicMaterialInstance_ReturnValue_2' has a wrong offset!");

}

