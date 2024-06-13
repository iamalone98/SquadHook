#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: L85A2_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass L85A2_Skeleton_AnimBlueprint.L85A2_Skeleton_AnimBlueprint_C
// 0x03C0 (0x06C0 - 0x0300)
class UL85A2_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0308(0x0030)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend_1;                  // 0x0338(0x00C0)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_3;                              // 0x03F8(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_2;                              // 0x0440(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x0488(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x04D0(0x0018)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x04E8(0x00C0)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x05A8(0x0080)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0628(0x0048)()
	struct FAnimNode_SequenceEvaluator            AnimGraphNode_SequenceEvaluator;                   // 0x0670(0x0050)()

public:
	void ExecuteUbergraph_L85A2_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"L85A2_Skeleton_AnimBlueprint_C">();
	}
	static class UL85A2_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UL85A2_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UL85A2_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UL85A2_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UL85A2_Skeleton_AnimBlueprint_C) == 0x0006C0, "Wrong size on UL85A2_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'UL85A2_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000308, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend_1) == 0x000338, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend_1' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_3) == 0x0003F8, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_3' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_2) == 0x000440, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_2' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x000488, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x0004D0, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x0004E8, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x0005A8, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000628, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UL85A2_Skeleton_AnimBlueprint_C, AnimGraphNode_SequenceEvaluator) == 0x000670, "Member 'UL85A2_Skeleton_AnimBlueprint_C::AnimGraphNode_SequenceEvaluator' has a wrong offset!");

}

