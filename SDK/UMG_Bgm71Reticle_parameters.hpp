#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Bgm71Reticle

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function UMG_Bgm71Reticle.UMG_Bgm71Reticle_C.ExecuteUbergraph_UMG_Bgm71Reticle
// 0x006C (0x006C - 0x0000)
struct UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetActorForwardVector_ReturnValue;        // 0x0004(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue;         // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_VInterpTo_ReturnValue;                    // 0x0014(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0020(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Subtract_VectorVector_ReturnValue;        // 0x005C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize_ReturnValue;                        // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle) == 0x000004, "Wrong alignment on UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle");
static_assert(sizeof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle) == 0x00006C, "Wrong size on UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, EntryPoint) == 0x000000, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::EntryPoint' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, CallFunc_GetActorForwardVector_ReturnValue) == 0x000004, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::CallFunc_GetActorForwardVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, CallFunc_GetWorldDeltaSeconds_ReturnValue) == 0x000010, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::CallFunc_GetWorldDeltaSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, CallFunc_VInterpTo_ReturnValue) == 0x000014, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::CallFunc_VInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, K2Node_Event_MyGeometry) == 0x000020, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, K2Node_Event_InDeltaTime) == 0x000058, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, CallFunc_Subtract_VectorVector_ReturnValue) == 0x00005C, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::CallFunc_Subtract_VectorVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle, CallFunc_VSize_ReturnValue) == 0x000068, "Member 'UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle::CallFunc_VSize_ReturnValue' has a wrong offset!");

// Function UMG_Bgm71Reticle.UMG_Bgm71Reticle_C.Tick
// 0x003C (0x003C - 0x0000)
struct UMG_Bgm71Reticle_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_Bgm71Reticle_C_Tick) == 0x000004, "Wrong alignment on UMG_Bgm71Reticle_C_Tick");
static_assert(sizeof(UMG_Bgm71Reticle_C_Tick) == 0x00003C, "Wrong size on UMG_Bgm71Reticle_C_Tick");
static_assert(offsetof(UMG_Bgm71Reticle_C_Tick, MyGeometry) == 0x000000, "Member 'UMG_Bgm71Reticle_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_Bgm71Reticle_C_Tick, InDeltaTime) == 0x000038, "Member 'UMG_Bgm71Reticle_C_Tick::InDeltaTime' has a wrong offset!");

}

