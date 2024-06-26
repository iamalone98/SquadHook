#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SK_EnforcerRWS_M2_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass SK_EnforcerRWS_M2_Skeleton_AnimBlueprint.SK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C
// 0x00A0 (0x0370 - 0x02D0)
class USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C final : public USQVehicleWeaponAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x02D8(0x0030)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0308(0x0048)()
	struct FAnimNode_RefPose                      AnimGraphNode_LocalRefPose;                        // 0x0350(0x0018)()

public:
	void ExecuteUbergraph_SK_EnforcerRWS_M2_Skeleton_AnimBlueprint(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C">();
	}
	static class USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C");
static_assert(sizeof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C) == 0x000370, "Wrong size on USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C");
static_assert(offsetof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x0002D0, "Member 'USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x0002D8, "Member 'USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000308, "Member 'USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C, AnimGraphNode_LocalRefPose) == 0x000350, "Member 'USK_EnforcerRWS_M2_Skeleton_AnimBlueprint_C::AnimGraphNode_LocalRefPose' has a wrong offset!");

}

