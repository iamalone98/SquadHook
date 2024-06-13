#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Rdg2_smoke_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass rdg2_smoke_Skeleton_AnimBlueprint.rdg2_smoke_Skeleton_AnimBlueprint_C
// 0x00A0 (0x0380 - 0x02E0)
class URdg2_smoke_Skeleton_AnimBlueprint_C final : public USQItemAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02E8(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0318(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x0360(0x0018)()

public:
	void ExecuteUbergraph_rdg2_smoke_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"rdg2_smoke_Skeleton_AnimBlueprint_C">();
	}
	static class URdg2_smoke_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<URdg2_smoke_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(URdg2_smoke_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on URdg2_smoke_Skeleton_AnimBlueprint_C");
static_assert(sizeof(URdg2_smoke_Skeleton_AnimBlueprint_C) == 0x000380, "Wrong size on URdg2_smoke_Skeleton_AnimBlueprint_C");
static_assert(offsetof(URdg2_smoke_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002E0, "Member 'URdg2_smoke_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(URdg2_smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002E8, "Member 'URdg2_smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(URdg2_smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000318, "Member 'URdg2_smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(URdg2_smoke_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x000360, "Member 'URdg2_smoke_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");

}
