#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RHIB_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass RHIB_Skeleton_AnimBlueprint.RHIB_Skeleton_AnimBlueprint_C
// 0x0640 (0x1120 - 0x0AE0)
class URHIB_Skeleton_AnimBlueprint_C final : public USQAmphibiousVehicleAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0AE0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0AE8(0x0030)()
	struct FAnimNode_MeshSpaceRefPose             AnimGraphNode_MeshRefPose;                         // 0x0B18(0x0010)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace;               // 0x0B28(0x0020)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_2;                        // 0x0B48(0x0108)()
	struct FAnimNode_SaveCachedPose               AnimGraphNode_SaveCachedPose;                      // 0x0C50(0x0158)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_1;                     // 0x0DA8(0x0028)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose;                       // 0x0DD0(0x0028)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x0DF8(0x0048)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x0E40(0x00C0)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_1;                        // 0x0F00(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone;                          // 0x1008(0x0108)()
	struct FRotator                               MotorRotation;                                     // 0x1110(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_RHIB_Skeleton_AnimBlueprint(int32 EntryPoint);
	void BlueprintUpdateAnimation(float DeltaTimeX);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"RHIB_Skeleton_AnimBlueprint_C">();
	}
	static class URHIB_Skeleton_AnimBlueprint_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<URHIB_Skeleton_AnimBlueprint_C>();
	}
};
static_assert(alignof(URHIB_Skeleton_AnimBlueprint_C) == 0x000010, "Wrong alignment on URHIB_Skeleton_AnimBlueprint_C");
static_assert(sizeof(URHIB_Skeleton_AnimBlueprint_C) == 0x001120, "Wrong size on URHIB_Skeleton_AnimBlueprint_C");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, UberGraphFrame) == 0x000AE0, "Member 'URHIB_Skeleton_AnimBlueprint_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_Root) == 0x000AE8, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_MeshRefPose) == 0x000B18, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_MeshRefPose' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_ComponentToLocalSpace) == 0x000B28, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_ComponentToLocalSpace' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_ModifyBone_2) == 0x000B48, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_ModifyBone_2' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_SaveCachedPose) == 0x000C50, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_SaveCachedPose' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_UseCachedPose_1) == 0x000DA8, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_UseCachedPose_1' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_UseCachedPose) == 0x000DD0, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_UseCachedPose' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_Slot) == 0x000DF8, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_LayeredBoneBlend) == 0x000E40, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_ModifyBone_1) == 0x000F00, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_ModifyBone_1' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, AnimGraphNode_ModifyBone) == 0x001008, "Member 'URHIB_Skeleton_AnimBlueprint_C::AnimGraphNode_ModifyBone' has a wrong offset!");
static_assert(offsetof(URHIB_Skeleton_AnimBlueprint_C, MotorRotation) == 0x001110, "Member 'URHIB_Skeleton_AnimBlueprint_C::MotorRotation' has a wrong offset!");

}

