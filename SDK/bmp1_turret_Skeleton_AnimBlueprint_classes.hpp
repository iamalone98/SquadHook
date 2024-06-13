#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: bmp1_turret_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass bmp1_turret_Skeleton_AnimBlueprint.bmp1_turret_Skeleton_AnimBlueprint_C
// 0x00A0 (0x0360 - 0x02C0)
class Ubmp1_turret_Skeleton_AnimBlueprint_C final : public UAnimInstance
{
public:
	uint8                                         Pad_4C57[0x8];                                     // 0x02B8(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02C0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02C8(0x0030)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x02F8(0x0018)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0310(0x0048)()

public:
	void ExecuteUbergraph_bmp1_turret_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"bmp1_turret_Skeleton_AnimBlueprint_C">();
	}
	static class Ubmp1_turret_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<Ubmp1_turret_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(Ubmp1_turret_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on Ubmp1_turret_Skeleton_AnimBlueprint_C");
static_assert(sizeof(Ubmp1_turret_Skeleton_AnimBlueprint_C) == 0x000360, "Wrong size on Ubmp1_turret_Skeleton_AnimBlueprint_C");
static_assert(offsetof(Ubmp1_turret_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002C0, "Member 'Ubmp1_turret_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(Ubmp1_turret_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002C8, "Member 'Ubmp1_turret_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(Ubmp1_turret_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x0002F8, "Member 'Ubmp1_turret_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");
static_assert(offsetof(Ubmp1_turret_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000310, "Member 'Ubmp1_turret_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");

}

