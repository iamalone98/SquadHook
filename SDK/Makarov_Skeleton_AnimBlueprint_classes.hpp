#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Makarov_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass Makarov_Skeleton_AnimBlueprint.Makarov_Skeleton_AnimBlueprint_C
// 0x0270 (0x0570 - 0x0300)
class UMakarov_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0308(0x0030)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x0338(0x00C0)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x03F8(0x0080)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_2;                              // 0x0478(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x04C0(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0508(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x0550(0x0018)()

public:
	void ExecuteUbergraph_Makarov_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Makarov_Skeleton_AnimBlueprint_C">();
	}
	static class UMakarov_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UMakarov_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UMakarov_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UMakarov_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UMakarov_Skeleton_AnimBlueprint_C) == 0x000570, "Wrong size on UMakarov_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'UMakarov_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000308, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x000338, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x0003F8, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_2) == 0x000478, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_2' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x0004C0, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000508, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UMakarov_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x000550, "Member 'UMakarov_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");

}
