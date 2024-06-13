#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Dshk_Cupola_Gun_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass Dshk_Cupola_Gun_Skeleton_AnimBlueprint.Dshk_Cupola_Gun_Skeleton_AnimBlueprint_C
// 0x03D0 (0x06A0 - 0x02D0)
class UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C final : public USQVehicleWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02D8(0x0030)()
	struct FAnimNode_RotationOffsetBlendSpace     AnimGraphNode_RotationOffsetBlendSpace;            // 0x0308(0x0190)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_2;                              // 0x0498(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x04E0(0x0018)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x04F8(0x00C0)()
	struct FAnimNode_SequenceEvaluator            AnimGraphNode_SequenceEvaluator;                   // 0x05B8(0x0050)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot_1;                              // 0x0608(0x0048)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0650(0x0048)()

public:
	void ExecuteUbergraph_Dshk_Cupola_Gun_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Dshk_Cupola_Gun_Skeleton_AnimBlueprint_C">();
	}
	static class UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C");
static_assert(sizeof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C) == 0x0006A0, "Wrong size on UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002D0, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002D8, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_RotationOffsetBlendSpace) == 0x000308, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_RotationOffsetBlendSpace' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_2) == 0x000498, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_2' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x0004E0, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x0004F8, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_SequenceEvaluator) == 0x0005B8, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_SequenceEvaluator' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot_1) == 0x000608, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot_1' has a wrong offset!");
static_assert(offsetof(UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000650, "Member 'UDshk_Cupola_Gun_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");

}

