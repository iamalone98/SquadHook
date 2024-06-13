#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: L132a1_Smoke_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass L132a1_Smoke_Skeleton_AnimBlueprint.L132a1_Smoke_Skeleton_AnimBlueprint_C
// 0x0150 (0x0450 - 0x0300)
class UL132a1_Smoke_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x0308(0x0048)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0350(0x0080)()
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x03D0(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0400(0x0048)()

public:
	void ExecuteUbergraph_L132a1_Smoke_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"L132a1_Smoke_Skeleton_AnimBlueprint_C">();
	}
	static class UL132a1_Smoke_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UL132a1_Smoke_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UL132a1_Smoke_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UL132a1_Smoke_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UL132a1_Smoke_Skeleton_AnimBlueprint_C) == 0x000450, "Wrong size on UL132a1_Smoke_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UL132a1_Smoke_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'UL132a1_Smoke_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UL132a1_Smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x000308, "Member 'UL132a1_Smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UL132a1_Smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x000350, "Member 'UL132a1_Smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UL132a1_Smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0003D0, "Member 'UL132a1_Smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UL132a1_Smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000400, "Member 'UL132a1_Smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");

}

