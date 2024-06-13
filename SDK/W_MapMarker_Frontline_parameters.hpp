#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapMarker_Frontline

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function W_MapMarker_Frontline.W_MapMarker_Frontline_C.ExecuteUbergraph_W_MapMarker_Frontline
// 0x0088 (0x0088 - 0x0000)
struct W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46BB[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x000C(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetActorForwardVector_ReturnValue;        // 0x0060(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1; // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_Conv_VectorToRotator_ReturnValue;         // 0x0070(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x007C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x0080(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0084(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline) == 0x000008, "Wrong alignment on W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline");
static_assert(sizeof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline) == 0x000088, "Wrong size on W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, EntryPoint) == 0x000000, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x000008, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, K2Node_Event_MyGeometry) == 0x00000C, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, K2Node_Event_InDeltaTime) == 0x000044, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000048, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00004C, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000050, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_PlayAnimation_ReturnValue) == 0x000058, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_GetActorForwardVector_ReturnValue) == 0x000060, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_GetActorForwardVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1) == 0x00006C, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel_1' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_Conv_VectorToRotator_ReturnValue) == 0x000070, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_Conv_VectorToRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_BreakRotator_Roll) == 0x00007C, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_BreakRotator_Pitch) == 0x000080, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline, CallFunc_BreakRotator_Yaw) == 0x000084, "Member 'W_MapMarker_Frontline_C_ExecuteUbergraph_W_MapMarker_Frontline::CallFunc_BreakRotator_Yaw' has a wrong offset!");

// Function W_MapMarker_Frontline.W_MapMarker_Frontline_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_MapMarker_Frontline_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_MapMarker_Frontline_C_Tick) == 0x000004, "Wrong alignment on W_MapMarker_Frontline_C_Tick");
static_assert(sizeof(W_MapMarker_Frontline_C_Tick) == 0x00003C, "Wrong size on W_MapMarker_Frontline_C_Tick");
static_assert(offsetof(W_MapMarker_Frontline_C_Tick, MyGeometry) == 0x000000, "Member 'W_MapMarker_Frontline_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MapMarker_Frontline_C_Tick, InDeltaTime) == 0x000038, "Member 'W_MapMarker_Frontline_C_Tick::InDeltaTime' has a wrong offset!");

}
