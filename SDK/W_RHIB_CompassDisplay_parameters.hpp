#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RHIB_CompassDisplay

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function W_RHIB_CompassDisplay.W_RHIB_CompassDisplay_C.ExecuteUbergraph_W_RHIB_CompassDisplay
// 0x00A0 (0x00A0 - 0x0000)
struct W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E44[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 K2Node_CustomEvent_OwningVehicle;                  // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E45[0x3];                                     // 0x0059(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FRotator                               CallFunc_K2_GetActorRotation_ReturnValue;          // 0x005C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_FloatFloat_ReturnValue;              // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E46[0x3];                                     // 0x0079(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x007C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Select_Default;                             // 0x0080(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2E47[0x4];                                     // 0x0084(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0088(0x0018)()
};
static_assert(alignof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay) == 0x000008, "Wrong alignment on W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay");
static_assert(sizeof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay) == 0x0000A0, "Wrong size on W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, EntryPoint) == 0x000000, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, K2Node_Event_MyGeometry) == 0x000004, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000040, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, Temp_bool_Variable) == 0x000048, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, K2Node_CustomEvent_OwningVehicle) == 0x000050, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::K2Node_CustomEvent_OwningVehicle' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_IsValid_ReturnValue) == 0x000058, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_K2_GetActorRotation_ReturnValue) == 0x00005C, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_K2_GetActorRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_BreakRotator_Roll) == 0x000068, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_BreakRotator_Pitch) == 0x00006C, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_BreakRotator_Yaw) == 0x000070, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_Add_FloatFloat_ReturnValue) == 0x000074, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_Less_FloatFloat_ReturnValue) == 0x000078, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_Less_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x00007C, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, K2Node_Select_Default) == 0x000080, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay, CallFunc_Conv_FloatToText_ReturnValue) == 0x000088, "Member 'W_RHIB_CompassDisplay_C_ExecuteUbergraph_W_RHIB_CompassDisplay::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");

// Function W_RHIB_CompassDisplay.W_RHIB_CompassDisplay_C.InitializeCompass
// 0x0008 (0x0008 - 0x0000)
struct W_RHIB_CompassDisplay_C_InitializeCompass final
{
public:
	class AActor*                                 Param_OwningVehicle;                               // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RHIB_CompassDisplay_C_InitializeCompass) == 0x000008, "Wrong alignment on W_RHIB_CompassDisplay_C_InitializeCompass");
static_assert(sizeof(W_RHIB_CompassDisplay_C_InitializeCompass) == 0x000008, "Wrong size on W_RHIB_CompassDisplay_C_InitializeCompass");
static_assert(offsetof(W_RHIB_CompassDisplay_C_InitializeCompass, Param_OwningVehicle) == 0x000000, "Member 'W_RHIB_CompassDisplay_C_InitializeCompass::Param_OwningVehicle' has a wrong offset!");

// Function W_RHIB_CompassDisplay.W_RHIB_CompassDisplay_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_RHIB_CompassDisplay_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_RHIB_CompassDisplay_C_Tick) == 0x000004, "Wrong alignment on W_RHIB_CompassDisplay_C_Tick");
static_assert(sizeof(W_RHIB_CompassDisplay_C_Tick) == 0x00003C, "Wrong size on W_RHIB_CompassDisplay_C_Tick");
static_assert(offsetof(W_RHIB_CompassDisplay_C_Tick, MyGeometry) == 0x000000, "Member 'W_RHIB_CompassDisplay_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_RHIB_CompassDisplay_C_Tick, InDeltaTime) == 0x000038, "Member 'W_RHIB_CompassDisplay_C_Tick::InDeltaTime' has a wrong offset!");

}

