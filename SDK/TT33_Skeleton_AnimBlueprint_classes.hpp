#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: TT33_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass TT33_Skeleton_AnimBlueprint.TT33_Skeleton_AnimBlueprint_C
// 0x02D0 (0x05D0 - 0x0300)
class UTT33_Skeleton_AnimBlueprint_C final : public USQWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0300(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0308(0x0030)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x0338(0x00C0)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_2;                              // 0x03F8(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x0440(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0488(0x0048)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer_1;                    // 0x04D0(0x0080)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0550(0x0080)()

public:
	void ExecuteUbergraph_TT33_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"TT33_Skeleton_AnimBlueprint_C">();
	}
	static class UTT33_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UTT33_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UTT33_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UTT33_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UTT33_Skeleton_AnimBlueprint_C) == 0x0005D0, "Wrong size on UTT33_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000300, "Member 'UTT33_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000308, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x000338, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_2) == 0x0003F8, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_2' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x000440, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000488, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer_1) == 0x0004D0, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer_1' has a wrong offset!");
static_assert(offsetof(UTT33_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x000550, "Member 'UTT33_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");

}

