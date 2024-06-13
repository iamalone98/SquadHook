#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MicrophoneVolume

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "MicrophoneVolume_structs.hpp"


namespace SDK::Params
{

// Function W_MicrophoneVolume.W_MicrophoneVolume_C.ExecuteUbergraph_W_MicrophoneVolume
// 0x0050 (0x0050 - 0x0000)
struct W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Whether_the_gate_is_currently_open_or_close_Variable; // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Has_Been_Initd_Variable;                 // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_IsClosed_Variable;                       // 0x0006(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2E1D[0x1];                                     // 0x0007(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0008(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EMicrophoneVolume                             CallFunc_GetMicrophoneVolume_DiscreteVolume;       // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2E1E[0x3];                                     // 0x0045(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetMicrophoneVolume_ReturnValue;          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_SwitchEnum_CmpSuccess;                      // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_SetMicrophoneForceAutoGain_ReturnValue;   // 0x004D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_SetMicrophoneForceAutoGain_ReturnValue_1; // 0x004E(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_SetMicrophoneForceAutoGain_ReturnValue_2; // 0x004F(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume) == 0x000004, "Wrong alignment on W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume");
static_assert(sizeof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume) == 0x000050, "Wrong size on W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, EntryPoint) == 0x000000, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, Temp_bool_Whether_the_gate_is_currently_open_or_close_Variable) == 0x000004, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::Temp_bool_Whether_the_gate_is_currently_open_or_close_Variable' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, Temp_bool_Has_Been_Initd_Variable) == 0x000005, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::Temp_bool_Has_Been_Initd_Variable' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, Temp_bool_IsClosed_Variable) == 0x000006, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::Temp_bool_IsClosed_Variable' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, K2Node_Event_MyGeometry) == 0x000008, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, K2Node_Event_InDeltaTime) == 0x000040, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, CallFunc_GetMicrophoneVolume_DiscreteVolume) == 0x000044, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::CallFunc_GetMicrophoneVolume_DiscreteVolume' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, CallFunc_GetMicrophoneVolume_ReturnValue) == 0x000048, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::CallFunc_GetMicrophoneVolume_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, K2Node_SwitchEnum_CmpSuccess) == 0x00004C, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::K2Node_SwitchEnum_CmpSuccess' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, CallFunc_SetMicrophoneForceAutoGain_ReturnValue) == 0x00004D, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::CallFunc_SetMicrophoneForceAutoGain_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, CallFunc_SetMicrophoneForceAutoGain_ReturnValue_1) == 0x00004E, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::CallFunc_SetMicrophoneForceAutoGain_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume, CallFunc_SetMicrophoneForceAutoGain_ReturnValue_2) == 0x00004F, "Member 'W_MicrophoneVolume_C_ExecuteUbergraph_W_MicrophoneVolume::CallFunc_SetMicrophoneForceAutoGain_ReturnValue_2' has a wrong offset!");

// Function W_MicrophoneVolume.W_MicrophoneVolume_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_MicrophoneVolume_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_MicrophoneVolume_C_Tick) == 0x000004, "Wrong alignment on W_MicrophoneVolume_C_Tick");
static_assert(sizeof(W_MicrophoneVolume_C_Tick) == 0x00003C, "Wrong size on W_MicrophoneVolume_C_Tick");
static_assert(offsetof(W_MicrophoneVolume_C_Tick, MyGeometry) == 0x000000, "Member 'W_MicrophoneVolume_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MicrophoneVolume_C_Tick, InDeltaTime) == 0x000038, "Member 'W_MicrophoneVolume_C_Tick::InDeltaTime' has a wrong offset!");

}

