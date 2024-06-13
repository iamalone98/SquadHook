#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RepairTool_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass RepairTool_Skeleton_AnimBlueprint.RepairTool_Skeleton_AnimBlueprint_C
// 0x0100 (0x03E0 - 0x02E0)
class URepairTool_Skeleton_AnimBlueprint_C final : public USQItemAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02E8(0x0030)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0318(0x0080)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0398(0x0048)()

public:
	void ExecuteUbergraph_RepairTool_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"RepairTool_Skeleton_AnimBlueprint_C">();
	}
	static class URepairTool_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<URepairTool_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(URepairTool_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on URepairTool_Skeleton_AnimBlueprint_C");
static_assert(sizeof(URepairTool_Skeleton_AnimBlueprint_C) == 0x0003E0, "Wrong size on URepairTool_Skeleton_AnimBlueprint_C");
static_assert(offsetof(URepairTool_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002E0, "Member 'URepairTool_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(URepairTool_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002E8, "Member 'URepairTool_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(URepairTool_Skeleton_AnimBlueprint_C, AnimGraphNode_SequencePlayer) == 0x000318, "Member 'URepairTool_Skeleton_AnimBlueprint_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(URepairTool_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000398, "Member 'URepairTool_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");

}

