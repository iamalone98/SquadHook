#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_DestructionObjectiveEvent

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_DestructionObjectiveEvent.W_DestructionObjectiveEvent_C.ExecuteUbergraph_W_DestructionObjectiveEvent
// 0x0070 (0x0070 - 0x0000)
struct W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         K2Node_CustomEvent_Objective_Owner;                // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0010(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetAnimationCurrentTime_ReturnValue;      // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAnimationPlaying_ReturnValue;           // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4971[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0054(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetEndTime_ReturnValue;                   // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x006C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent) == 0x000008, "Wrong alignment on W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent");
static_assert(sizeof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent) == 0x000070, "Wrong size on W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, EntryPoint) == 0x000000, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, K2Node_CustomEvent_Objective_Owner) == 0x000004, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::K2Node_CustomEvent_Objective_Owner' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000008, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, K2Node_Event_MyGeometry) == 0x000010, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, K2Node_Event_InDeltaTime) == 0x000048, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_GetAnimationCurrentTime_ReturnValue) == 0x00004C, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_GetAnimationCurrentTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_IsAnimationPlaying_ReturnValue) == 0x000050, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_IsAnimationPlaying_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_Add_FloatFloat_ReturnValue) == 0x000054, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000058, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_FClamp_ReturnValue) == 0x00005C, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_PlayAnimation_ReturnValue) == 0x000060, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_GetEndTime_ReturnValue) == 0x000068, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_GetEndTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x00006C, "Member 'W_DestructionObjectiveEvent_C_ExecuteUbergraph_W_DestructionObjectiveEvent::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");

// Function W_DestructionObjectiveEvent.W_DestructionObjectiveEvent_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_DestructionObjectiveEvent_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_DestructionObjectiveEvent_C_Tick) == 0x000004, "Wrong alignment on W_DestructionObjectiveEvent_C_Tick");
static_assert(sizeof(W_DestructionObjectiveEvent_C_Tick) == 0x00003C, "Wrong size on W_DestructionObjectiveEvent_C_Tick");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Tick, MyGeometry) == 0x000000, "Member 'W_DestructionObjectiveEvent_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Tick, InDeltaTime) == 0x000038, "Member 'W_DestructionObjectiveEvent_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_DestructionObjectiveEvent.W_DestructionObjectiveEvent_C.Play Destroy Animation
// 0x0004 (0x0004 - 0x0000)
struct W_DestructionObjectiveEvent_C_Play_Destroy_Animation final
{
public:
	int32                                         Param_Objective_Owner;                             // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_DestructionObjectiveEvent_C_Play_Destroy_Animation) == 0x000004, "Wrong alignment on W_DestructionObjectiveEvent_C_Play_Destroy_Animation");
static_assert(sizeof(W_DestructionObjectiveEvent_C_Play_Destroy_Animation) == 0x000004, "Wrong size on W_DestructionObjectiveEvent_C_Play_Destroy_Animation");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Play_Destroy_Animation, Param_Objective_Owner) == 0x000000, "Member 'W_DestructionObjectiveEvent_C_Play_Destroy_Animation::Param_Objective_Owner' has a wrong offset!");

// Function W_DestructionObjectiveEvent.W_DestructionObjectiveEvent_C.Setup Fill Image
// 0x0020 (0x0020 - 0x0000)
struct W_DestructionObjectiveEvent_C_Setup_Fill_Image final
{
public:
	int32                                         CallFunc_TryGetLocalPlayerTeamId_OutTeamId;        // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetLocalPlayerTeamId_ReturnValue;      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4972[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           CallFunc_SelectColor_ReturnValue;                  // 0x0010(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_DestructionObjectiveEvent_C_Setup_Fill_Image) == 0x000008, "Wrong alignment on W_DestructionObjectiveEvent_C_Setup_Fill_Image");
static_assert(sizeof(W_DestructionObjectiveEvent_C_Setup_Fill_Image) == 0x000020, "Wrong size on W_DestructionObjectiveEvent_C_Setup_Fill_Image");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Setup_Fill_Image, CallFunc_TryGetLocalPlayerTeamId_OutTeamId) == 0x000000, "Member 'W_DestructionObjectiveEvent_C_Setup_Fill_Image::CallFunc_TryGetLocalPlayerTeamId_OutTeamId' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Setup_Fill_Image, CallFunc_TryGetLocalPlayerTeamId_ReturnValue) == 0x000004, "Member 'W_DestructionObjectiveEvent_C_Setup_Fill_Image::CallFunc_TryGetLocalPlayerTeamId_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Setup_Fill_Image, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000005, "Member 'W_DestructionObjectiveEvent_C_Setup_Fill_Image::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Setup_Fill_Image, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'W_DestructionObjectiveEvent_C_Setup_Fill_Image::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_DestructionObjectiveEvent_C_Setup_Fill_Image, CallFunc_SelectColor_ReturnValue) == 0x000010, "Member 'W_DestructionObjectiveEvent_C_Setup_Fill_Image::CallFunc_SelectColor_ReturnValue' has a wrong offset!");

}
