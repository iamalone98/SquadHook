#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SPG9_HEAT_Reticle

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function SPG9_HEAT_Reticle.SPG9_HEAT_Reticle_C.ExecuteUbergraph_SPG9_HEAT_Reticle
// 0x0058 (0x0058 - 0x0000)
struct SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4618[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UImage*>                         K2Node_MakeArray_Array;                            // 0x0008(0x0010)(ReferenceParm, ContainsInstancedReference)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0018(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle) == 0x000008, "Wrong alignment on SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle");
static_assert(sizeof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle) == 0x000058, "Wrong size on SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle");
static_assert(offsetof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle, EntryPoint) == 0x000000, "Member 'SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle::EntryPoint' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle, K2Node_MakeArray_Array) == 0x000008, "Member 'SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle, K2Node_Event_MyGeometry) == 0x000018, "Member 'SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle, K2Node_Event_InDeltaTime) == 0x000050, "Member 'SPG9_HEAT_Reticle_C_ExecuteUbergraph_SPG9_HEAT_Reticle::K2Node_Event_InDeltaTime' has a wrong offset!");

// Function SPG9_HEAT_Reticle.SPG9_HEAT_Reticle_C.Tick
// 0x003C (0x003C - 0x0000)
struct SPG9_HEAT_Reticle_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SPG9_HEAT_Reticle_C_Tick) == 0x000004, "Wrong alignment on SPG9_HEAT_Reticle_C_Tick");
static_assert(sizeof(SPG9_HEAT_Reticle_C_Tick) == 0x00003C, "Wrong size on SPG9_HEAT_Reticle_C_Tick");
static_assert(offsetof(SPG9_HEAT_Reticle_C_Tick, MyGeometry) == 0x000000, "Member 'SPG9_HEAT_Reticle_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_Tick, InDeltaTime) == 0x000038, "Member 'SPG9_HEAT_Reticle_C_Tick::InDeltaTime' has a wrong offset!");

// Function SPG9_HEAT_Reticle.SPG9_HEAT_Reticle_C.TunnelOffset
// 0x00C0 (0x00C0 - 0x0000)
struct SPG9_HEAT_Reticle_C_TunnelOffset final
{
public:
	float                                         RangeOfMotion;                                     // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Multiplier;                                        // 0x0004(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         InterpSpeed;                                       // 0x0008(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4619[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UWidget*                                TunnelImg;                                         // 0x0010(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UWidget*                                Reticle;                                           // 0x0018(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_1;        // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_461A[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerCameraManager*                   CallFunc_GetPlayerCameraManager_ReturnValue;       // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue;         // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_K2_GetActorRotation_ReturnValue;          // 0x0044(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FRotator                               CallFunc_RInterpTo_ReturnValue;                    // 0x0050(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue_1;       // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Roll_1;                      // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch_1;                     // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw_1;                       // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_1;        // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_2;        // 0x0078(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_3;        // 0x007C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue_1;                     // 0x0080(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x0084(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Vector2DInterpTo_ReturnValue;             // 0x008C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X;                          // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue_2;                     // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue_3;                     // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_1;               // 0x00AC(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Multiply_Vector2DFloat_ReturnValue;       // 0x00B4(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SPG9_HEAT_Reticle_C_TunnelOffset) == 0x000008, "Wrong alignment on SPG9_HEAT_Reticle_C_TunnelOffset");
static_assert(sizeof(SPG9_HEAT_Reticle_C_TunnelOffset) == 0x0000C0, "Wrong size on SPG9_HEAT_Reticle_C_TunnelOffset");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, RangeOfMotion) == 0x000000, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::RangeOfMotion' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, Multiplier) == 0x000004, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::Multiplier' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, InterpSpeed) == 0x000008, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::InterpSpeed' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, TunnelImg) == 0x000010, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::TunnelImg' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, Reticle) == 0x000018, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::Reticle' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Roll) == 0x000020, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Pitch) == 0x000024, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Yaw) == 0x000028, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00002C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Multiply_FloatFloat_ReturnValue_1) == 0x000030, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Multiply_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_GetPlayerCameraManager_ReturnValue) == 0x000038, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_GetPlayerCameraManager_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_GetWorldDeltaSeconds_ReturnValue) == 0x000040, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_GetWorldDeltaSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_K2_GetActorRotation_ReturnValue) == 0x000044, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_K2_GetActorRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_RInterpTo_ReturnValue) == 0x000050, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_RInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_GetWorldDeltaSeconds_ReturnValue_1) == 0x00005C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_GetWorldDeltaSeconds_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Roll_1) == 0x000060, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Roll_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Pitch_1) == 0x000064, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Pitch_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakRotator_Yaw_1) == 0x000068, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakRotator_Yaw_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_FClamp_ReturnValue) == 0x00006C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000070, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Subtract_FloatFloat_ReturnValue_1) == 0x000074, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Subtract_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Multiply_FloatFloat_ReturnValue_2) == 0x000078, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Multiply_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Multiply_FloatFloat_ReturnValue_3) == 0x00007C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Multiply_FloatFloat_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_FClamp_ReturnValue_1) == 0x000080, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_FClamp_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_MakeVector2D_ReturnValue) == 0x000084, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Vector2DInterpTo_ReturnValue) == 0x00008C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Vector2DInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakVector2D_X) == 0x000094, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_BreakVector2D_Y) == 0x000098, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00009C, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x0000A0, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_FClamp_ReturnValue_2) == 0x0000A4, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_FClamp_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_FClamp_ReturnValue_3) == 0x0000A8, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_FClamp_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_MakeVector2D_ReturnValue_1) == 0x0000AC, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_MakeVector2D_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SPG9_HEAT_Reticle_C_TunnelOffset, CallFunc_Multiply_Vector2DFloat_ReturnValue) == 0x0000B4, "Member 'SPG9_HEAT_Reticle_C_TunnelOffset::CallFunc_Multiply_Vector2DFloat_ReturnValue' has a wrong offset!");

}

