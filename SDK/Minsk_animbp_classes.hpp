#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Minsk_animbp

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "PhysXVehicles_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass minsk_animbp.minsk_animbp_C
// 0x1A40 (0x24F0 - 0x0AB0)
class UMinsk_animbp_C final : public USQVehicleAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0AB0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x0AB8(0x0030)()
	struct FAnimNode_MeshSpaceRefPose             AnimGraphNode_MeshRefPose;                         // 0x0AE8(0x0010)()
	struct FAnimNode_WheelHandler                 AnimGraphNode_WheelHandler;                        // 0x0AF8(0x00E0)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace_3;             // 0x0BD8(0x0020)()
	struct FAnimNode_BoneDrivenController         AnimGraphNode_BoneDrivenController_4;              // 0x0BF8(0x0118)()
	struct FAnimNode_LookAt                       AnimGraphNode_LookAt_3;                            // 0x0D10(0x01B0)()
	struct FAnimNode_LookAt                       AnimGraphNode_LookAt_2;                            // 0x0EC0(0x01B0)()
	struct FAnimNode_CopyBone                     AnimGraphNode_CopyBone_2;                          // 0x1070(0x00F0)()
	struct FAnimNode_CopyBone                     AnimGraphNode_CopyBone_1;                          // 0x1160(0x00F0)()
	struct FAnimNode_CopyBone                     AnimGraphNode_CopyBone;                            // 0x1250(0x00F0)()
	struct FAnimNode_LookAt                       AnimGraphNode_LookAt_1;                            // 0x1340(0x01B0)()
	struct FAnimNode_BoneDrivenController         AnimGraphNode_BoneDrivenController_3;              // 0x14F0(0x0118)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_3;                        // 0x1608(0x0108)()
	struct FAnimNode_LookAt                       AnimGraphNode_LookAt;                              // 0x1710(0x01B0)()
	struct FAnimNode_BoneDrivenController         AnimGraphNode_BoneDrivenController_2;              // 0x18C0(0x0118)()
	struct FAnimNode_SaveCachedPose               AnimGraphNode_SaveCachedPose_1;                    // 0x19D8(0x0158)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_3;                     // 0x1B30(0x0028)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_2;                     // 0x1B58(0x0028)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x1B80(0x00C0)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x1C40(0x0048)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_2;                        // 0x1C88(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_1;                        // 0x1D90(0x0108)()
	struct FAnimNode_BlendListByBool              AnimGraphNode_BlendListByBool;                     // 0x1E98(0x00A0)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace_2;             // 0x1F38(0x0020)()
	struct FAnimNode_SaveCachedPose               AnimGraphNode_SaveCachedPose;                      // 0x1F58(0x0158)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_1;                     // 0x20B0(0x0028)()
	struct FAnimNode_ConvertLocalToComponentSpace AnimGraphNode_LocalToComponentSpace_2;             // 0x20D8(0x0020)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace_1;             // 0x20F8(0x0020)()
	struct FAnimNode_ConvertLocalToComponentSpace AnimGraphNode_LocalToComponentSpace_1;             // 0x2118(0x0020)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone;                          // 0x2138(0x0108)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose;                       // 0x2240(0x0028)()
	struct FAnimNode_ConvertLocalToComponentSpace AnimGraphNode_LocalToComponentSpace;               // 0x2268(0x0020)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace;               // 0x2288(0x0020)()
	struct FAnimNode_BoneDrivenController         AnimGraphNode_BoneDrivenController_1;              // 0x22A8(0x0118)()
	struct FAnimNode_BoneDrivenController         AnimGraphNode_BoneDrivenController;                // 0x23C0(0x0118)()
	struct FVector                                Wheel_Front_Scale;                                 // 0x24D8(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                Wheel_Rear_Scale;                                  // 0x24E4(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_minsk_animbp(int32 EntryPoint);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"minsk_animbp_C">();
	}
	static class UMinsk_animbp_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UMinsk_animbp_C>();
	}
};
static_assert(alignof(UMinsk_animbp_C) == 0x000010, "Wrong alignment on UMinsk_animbp_C");
static_assert(sizeof(UMinsk_animbp_C) == 0x0024F0, "Wrong size on UMinsk_animbp_C");
static_assert(offsetof(UMinsk_animbp_C, UberGraphFrame) == 0x000AB0, "Member 'UMinsk_animbp_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_Root) == 0x000AB8, "Member 'UMinsk_animbp_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_MeshRefPose) == 0x000AE8, "Member 'UMinsk_animbp_C::AnimGraphNode_MeshRefPose' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_WheelHandler) == 0x000AF8, "Member 'UMinsk_animbp_C::AnimGraphNode_WheelHandler' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ComponentToLocalSpace_3) == 0x000BD8, "Member 'UMinsk_animbp_C::AnimGraphNode_ComponentToLocalSpace_3' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BoneDrivenController_4) == 0x000BF8, "Member 'UMinsk_animbp_C::AnimGraphNode_BoneDrivenController_4' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LookAt_3) == 0x000D10, "Member 'UMinsk_animbp_C::AnimGraphNode_LookAt_3' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LookAt_2) == 0x000EC0, "Member 'UMinsk_animbp_C::AnimGraphNode_LookAt_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_CopyBone_2) == 0x001070, "Member 'UMinsk_animbp_C::AnimGraphNode_CopyBone_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_CopyBone_1) == 0x001160, "Member 'UMinsk_animbp_C::AnimGraphNode_CopyBone_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_CopyBone) == 0x001250, "Member 'UMinsk_animbp_C::AnimGraphNode_CopyBone' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LookAt_1) == 0x001340, "Member 'UMinsk_animbp_C::AnimGraphNode_LookAt_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BoneDrivenController_3) == 0x0014F0, "Member 'UMinsk_animbp_C::AnimGraphNode_BoneDrivenController_3' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ModifyBone_3) == 0x001608, "Member 'UMinsk_animbp_C::AnimGraphNode_ModifyBone_3' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LookAt) == 0x001710, "Member 'UMinsk_animbp_C::AnimGraphNode_LookAt' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BoneDrivenController_2) == 0x0018C0, "Member 'UMinsk_animbp_C::AnimGraphNode_BoneDrivenController_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_SaveCachedPose_1) == 0x0019D8, "Member 'UMinsk_animbp_C::AnimGraphNode_SaveCachedPose_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_UseCachedPose_3) == 0x001B30, "Member 'UMinsk_animbp_C::AnimGraphNode_UseCachedPose_3' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_UseCachedPose_2) == 0x001B58, "Member 'UMinsk_animbp_C::AnimGraphNode_UseCachedPose_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LayeredBoneBlend) == 0x001B80, "Member 'UMinsk_animbp_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_Slot) == 0x001C40, "Member 'UMinsk_animbp_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ModifyBone_2) == 0x001C88, "Member 'UMinsk_animbp_C::AnimGraphNode_ModifyBone_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ModifyBone_1) == 0x001D90, "Member 'UMinsk_animbp_C::AnimGraphNode_ModifyBone_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BlendListByBool) == 0x001E98, "Member 'UMinsk_animbp_C::AnimGraphNode_BlendListByBool' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ComponentToLocalSpace_2) == 0x001F38, "Member 'UMinsk_animbp_C::AnimGraphNode_ComponentToLocalSpace_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_SaveCachedPose) == 0x001F58, "Member 'UMinsk_animbp_C::AnimGraphNode_SaveCachedPose' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_UseCachedPose_1) == 0x0020B0, "Member 'UMinsk_animbp_C::AnimGraphNode_UseCachedPose_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LocalToComponentSpace_2) == 0x0020D8, "Member 'UMinsk_animbp_C::AnimGraphNode_LocalToComponentSpace_2' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ComponentToLocalSpace_1) == 0x0020F8, "Member 'UMinsk_animbp_C::AnimGraphNode_ComponentToLocalSpace_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LocalToComponentSpace_1) == 0x002118, "Member 'UMinsk_animbp_C::AnimGraphNode_LocalToComponentSpace_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ModifyBone) == 0x002138, "Member 'UMinsk_animbp_C::AnimGraphNode_ModifyBone' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_UseCachedPose) == 0x002240, "Member 'UMinsk_animbp_C::AnimGraphNode_UseCachedPose' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_LocalToComponentSpace) == 0x002268, "Member 'UMinsk_animbp_C::AnimGraphNode_LocalToComponentSpace' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_ComponentToLocalSpace) == 0x002288, "Member 'UMinsk_animbp_C::AnimGraphNode_ComponentToLocalSpace' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BoneDrivenController_1) == 0x0022A8, "Member 'UMinsk_animbp_C::AnimGraphNode_BoneDrivenController_1' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, AnimGraphNode_BoneDrivenController) == 0x0023C0, "Member 'UMinsk_animbp_C::AnimGraphNode_BoneDrivenController' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, Wheel_Front_Scale) == 0x0024D8, "Member 'UMinsk_animbp_C::Wheel_Front_Scale' has a wrong offset!");
static_assert(offsetof(UMinsk_animbp_C, Wheel_Rear_Scale) == 0x0024E4, "Member 'UMinsk_animbp_C::Wheel_Rear_Scale' has a wrong offset!");

}

