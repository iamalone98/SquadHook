#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FV510_gun_AnimBp

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass FV510_gun_AnimBp.FV510_gun_AnimBp_C
// 0x00A0 (0x0360 - 0x02C0)
class UFV510_gun_AnimBp_C final : public UAnimInstance
{
public:
	uint8                                         Pad_4D55[0x8];                                     // 0x02B8(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02C0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02C8(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x02F8(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x0340(0x0018)()

public:
	void ExecuteUbergraph_FV510_gun_AnimBp(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"FV510_gun_AnimBp_C">();
	}
	static class UFV510_gun_AnimBp_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UFV510_gun_AnimBp_C>();
	}
};
static_assert(alignof(UFV510_gun_AnimBp_C) == 0x000010, "Wrong alignment on UFV510_gun_AnimBp_C");
static_assert(sizeof(UFV510_gun_AnimBp_C) == 0x000360, "Wrong size on UFV510_gun_AnimBp_C");
static_assert(offsetof(UFV510_gun_AnimBp_C, UberGraphFrame) == 0x0002C0, "Member 'UFV510_gun_AnimBp_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UFV510_gun_AnimBp_C, AnimGraphNode_Root) == 0x0002C8, "Member 'UFV510_gun_AnimBp_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UFV510_gun_AnimBp_C, AnimGraphNode_Slot) == 0x0002F8, "Member 'UFV510_gun_AnimBp_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UFV510_gun_AnimBp_C, AnimGraphNode_LocalRefPose) == 0x000340, "Member 'UFV510_gun_AnimBp_C::AnimGraphNode_LocalRefPose' has a wrong offset!");

}

