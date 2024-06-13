#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Ppsh41_drum_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass ppsh41_drum_Skeleton_AnimBlueprint.ppsh41_drum_Skeleton_AnimBlueprint_C
// 0x03E0 (0x06E0 - 0x0300)
class UPpsh41_drum_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0308(0x0030)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend_1;                  // 0x0338(0x00C0)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer_1;                    // 0x03F8(0x0080)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_2;                              // 0x0478(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x04C0(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0508(0x0048)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0550(0x0080)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x05D0(0x00C0)()
	struct FAnimNode_SequenceEvaluator            AnimGraphNode_SequenceEvaluator;                   // 0x0690(0x0050)()

public:
	void ExecuteUbergraph_ppsh41_drum_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"ppsh41_drum_Skeleton_AnimBlueprint_C">();
	}
	static class UPpsh41_drum_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UPpsh41_drum_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UPpsh41_drum_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UPpsh41_drum_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UPpsh41_drum_Skeleton_AnimBlueprint_C) == 0x0006E0, "Wrong size on UPpsh41_drum_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000308, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend_1) == 0x000338, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend_1' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer_1) == 0x0003F8, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer_1' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_2) == 0x000478, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_2' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x0004C0, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000508, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x000550, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x0005D0, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UPpsh41_drum_Skeleton_AnimBlueprint_C, AnimGraphNode_SequenceEvaluator) == 0x000690, "Member 'UPpsh41_drum_Skeleton_AnimBlueprint_C::AnimGraphNode_SequenceEvaluator' has a wrong offset!");

}
