#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Director_FrontlineGold

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function W_Director_FrontlineGold.W_Director_FrontlineGold_C.ExecuteUbergraph_W_Director_FrontlineGold
// 0x0070 (0x0070 - 0x0000)
struct W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Get_Pixel_Distance_Distance;              // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x000C(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3314[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Get_Angle_Widget_Angle;                   // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_Get_Angle_World_Rotation;                 // 0x005C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold) == 0x000008, "Wrong alignment on W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold");
static_assert(sizeof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold) == 0x000070, "Wrong size on W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, EntryPoint) == 0x000000, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Get_Pixel_Distance_Distance) == 0x000004, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Get_Pixel_Distance_Distance' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000008, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, K2Node_Event_MyGeometry) == 0x00000C, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, K2Node_Event_InDeltaTime) == 0x000044, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000048, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000050, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Get_Angle_Widget_Angle) == 0x000058, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Get_Angle_Widget_Angle' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Get_Angle_World_Rotation) == 0x00005C, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Get_Angle_World_Rotation' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold, CallFunc_Add_FloatFloat_ReturnValue) == 0x000068, "Member 'W_Director_FrontlineGold_C_ExecuteUbergraph_W_Director_FrontlineGold::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");

// Function W_Director_FrontlineGold.W_Director_FrontlineGold_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_Director_FrontlineGold_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Director_FrontlineGold_C_Tick) == 0x000004, "Wrong alignment on W_Director_FrontlineGold_C_Tick");
static_assert(sizeof(W_Director_FrontlineGold_C_Tick) == 0x00003C, "Wrong size on W_Director_FrontlineGold_C_Tick");
static_assert(offsetof(W_Director_FrontlineGold_C_Tick, MyGeometry) == 0x000000, "Member 'W_Director_FrontlineGold_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Director_FrontlineGold_C_Tick, InDeltaTime) == 0x000038, "Member 'W_Director_FrontlineGold_C_Tick::InDeltaTime' has a wrong offset!");

}

