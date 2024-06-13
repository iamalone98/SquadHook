#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: TM62_Mine_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass TM62_Mine_Skeleton_AnimBlueprint.TM62_Mine_Skeleton_AnimBlueprint_C
// 0x0100 (0x03E0 - 0x02E0)
class UTM62_Mine_Skeleton_AnimBlueprint_C final : public USQItemAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02E8(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0318(0x0048)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0360(0x0080)()

public:
	void ExecuteUbergraph_TM62_Mine_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"TM62_Mine_Skeleton_AnimBlueprint_C">();
	}
	static class UTM62_Mine_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UTM62_Mine_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UTM62_Mine_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UTM62_Mine_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UTM62_Mine_Skeleton_AnimBlueprint_C) == 0x0003E0, "Wrong size on UTM62_Mine_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UTM62_Mine_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002E0, "Member 'UTM62_Mine_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UTM62_Mine_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002E8, "Member 'UTM62_Mine_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UTM62_Mine_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000318, "Member 'UTM62_Mine_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UTM62_Mine_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x000360, "Member 'UTM62_Mine_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");

}

