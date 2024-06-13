#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SovietBinoculars_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass SovietBinoculars_Skeleton_AnimBlueprint.SovietBinoculars_Skeleton_AnimBlueprint_C
// 0x00E0 (0x03E0 - 0x0300)
class USovietBinoculars_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0308(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x0338(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0380(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x03C8(0x0018)()

public:
	void ExecuteUbergraph_SovietBinoculars_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SovietBinoculars_Skeleton_AnimBlueprint_C">();
	}
	static class USovietBinoculars_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USovietBinoculars_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(USovietBinoculars_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on USovietBinoculars_Skeleton_AnimBlueprint_C");
static_assert(sizeof(USovietBinoculars_Skeleton_AnimBlueprint_C) == 0x0003E0, "Wrong size on USovietBinoculars_Skeleton_AnimBlueprint_C");
static_assert(offsetof(USovietBinoculars_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'USovietBinoculars_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(USovietBinoculars_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000308, "Member 'USovietBinoculars_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(USovietBinoculars_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x000338, "Member 'USovietBinoculars_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(USovietBinoculars_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000380, "Member 'USovietBinoculars_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(USovietBinoculars_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x0003C8, "Member 'USovietBinoculars_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");

}
