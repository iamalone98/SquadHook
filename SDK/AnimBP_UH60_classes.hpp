#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: AnimBP_UH60

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass AnimBP_UH60.AnimBP_UH60_C
// 0x2170 (0x2C20 - 0x0AB0)
class UAnimBP_UH60_C final : public USQVehicleAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0AB0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_27;                       // 0x0AB8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_26;                       // 0x0BC0(0x0108)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x0CC8(0x0080)()
	struct FAnimNode_ConvertLocalToComponentSpace AnimGraphNode_LocalToComponentSpace;               // 0x0D48(0x0020)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace;               // 0x0D68(0x0020)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_25;                       // 0x0D88(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_24;                       // 0x0E90(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_23;                       // 0x0F98(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_22;                       // 0x10A0(0x0108)()
	struct FAnimNode_SaveCachedPose               AnimGraphNode_SaveCachedPose;                      // 0x11A8(0x0158)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_1;                     // 0x1300(0x0028)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose;                       // 0x1328(0x0028)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x1350(0x00C0)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x1410(0x0048)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_21;                       // 0x1458(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_20;                       // 0x1560(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_19;                       // 0x1668(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_18;                       // 0x1770(0x0108)()
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x1878(0x0030)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_17;                       // 0x18A8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_16;                       // 0x19B0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_15;                       // 0x1AB8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_14;                       // 0x1BC0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_13;                       // 0x1CC8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_12;                       // 0x1DD0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_11;                       // 0x1ED8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_10;                       // 0x1FE0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_9;                        // 0x20E8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_8;                        // 0x21F0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_7;                        // 0x22F8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_6;                        // 0x2400(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_5;                        // 0x2508(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_4;                        // 0x2610(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_3;                        // 0x2718(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_2;                        // 0x2820(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_1;                        // 0x2928(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone;                          // 0x2A30(0x0108)()
	struct FRotator                               MainRotorRotation;                                 // 0x2B38(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailRotorRotation;                                 // 0x2B44(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence0;                                    // 0x2B50(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence1;                                    // 0x2B5C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	float                                         BladesLiftAlpha;                                   // 0x2B68(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               MainIncidence2;                                    // 0x2B6C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence3;                                    // 0x2B78(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	float                                         MaxLiftDegrees;                                    // 0x2B84(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               TailIncidence0;                                    // 0x2B88(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence1;                                    // 0x2B94(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence2;                                    // 0x2BA0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence3;                                    // 0x2BAC(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               RearTailRot;                                       // 0x2BB8(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               ControlStickRot;                                   // 0x2BC4(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FVector                                MainBladesBlurScale;                               // 0x2BD0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                MainBladesScale;                                   // 0x2BDC(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailBladesBlurScale;                               // 0x2BE8(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailBladesScale;                                   // 0x2BF4(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                MainRotorScale;                                    // 0x2C00(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailRotorScale;                                    // 0x2C0C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_AnimBP_UH60(int32 EntryPoint);
	void BlueprintUpdateAnimation(float DeltaTimeX);
	void GetCurrentRotorRPM(class ABP_Generic_Helicopter_C* Helicopter, bool Main, float* RPM);
	void RPMtoDegPerSec(float RPM, bool MainRotor, class ABP_UH60_C* Helicopter, float* DegPerSec);
	void GetBladesScale(class ABP_Generic_Helicopter_C* Helicopter, bool Main, struct FVector* Blades, struct FVector* BlurBlades);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"AnimBP_UH60_C">();
	}
	static class UAnimBP_UH60_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UAnimBP_UH60_C>();
	}
};
static_assert(alignof(UAnimBP_UH60_C) == 0x000010, "Wrong alignment on UAnimBP_UH60_C");
static_assert(sizeof(UAnimBP_UH60_C) == 0x002C20, "Wrong size on UAnimBP_UH60_C");
static_assert(offsetof(UAnimBP_UH60_C, UberGraphFrame) == 0x000AB0, "Member 'UAnimBP_UH60_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_27) == 0x000AB8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_27' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_26) == 0x000BC0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_26' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_SequencePlayer) == 0x000CC8, "Member 'UAnimBP_UH60_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_LocalToComponentSpace) == 0x000D48, "Member 'UAnimBP_UH60_C::AnimGraphNode_LocalToComponentSpace' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ComponentToLocalSpace) == 0x000D68, "Member 'UAnimBP_UH60_C::AnimGraphNode_ComponentToLocalSpace' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_25) == 0x000D88, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_25' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_24) == 0x000E90, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_24' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_23) == 0x000F98, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_23' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_22) == 0x0010A0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_22' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_SaveCachedPose) == 0x0011A8, "Member 'UAnimBP_UH60_C::AnimGraphNode_SaveCachedPose' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_UseCachedPose_1) == 0x001300, "Member 'UAnimBP_UH60_C::AnimGraphNode_UseCachedPose_1' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_UseCachedPose) == 0x001328, "Member 'UAnimBP_UH60_C::AnimGraphNode_UseCachedPose' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_LayeredBoneBlend) == 0x001350, "Member 'UAnimBP_UH60_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_Slot) == 0x001410, "Member 'UAnimBP_UH60_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_21) == 0x001458, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_21' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_20) == 0x001560, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_20' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_19) == 0x001668, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_19' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_18) == 0x001770, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_18' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_Root) == 0x001878, "Member 'UAnimBP_UH60_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_17) == 0x0018A8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_17' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_16) == 0x0019B0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_16' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_15) == 0x001AB8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_15' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_14) == 0x001BC0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_14' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_13) == 0x001CC8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_13' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_12) == 0x001DD0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_12' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_11) == 0x001ED8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_11' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_10) == 0x001FE0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_10' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_9) == 0x0020E8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_9' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_8) == 0x0021F0, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_8' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_7) == 0x0022F8, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_7' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_6) == 0x002400, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_6' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_5) == 0x002508, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_5' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_4) == 0x002610, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_4' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_3) == 0x002718, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_3' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_2) == 0x002820, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_2' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone_1) == 0x002928, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone_1' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, AnimGraphNode_ModifyBone) == 0x002A30, "Member 'UAnimBP_UH60_C::AnimGraphNode_ModifyBone' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainRotorRotation) == 0x002B38, "Member 'UAnimBP_UH60_C::MainRotorRotation' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailRotorRotation) == 0x002B44, "Member 'UAnimBP_UH60_C::TailRotorRotation' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainIncidence0) == 0x002B50, "Member 'UAnimBP_UH60_C::MainIncidence0' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainIncidence1) == 0x002B5C, "Member 'UAnimBP_UH60_C::MainIncidence1' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, BladesLiftAlpha) == 0x002B68, "Member 'UAnimBP_UH60_C::BladesLiftAlpha' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainIncidence2) == 0x002B6C, "Member 'UAnimBP_UH60_C::MainIncidence2' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainIncidence3) == 0x002B78, "Member 'UAnimBP_UH60_C::MainIncidence3' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MaxLiftDegrees) == 0x002B84, "Member 'UAnimBP_UH60_C::MaxLiftDegrees' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailIncidence0) == 0x002B88, "Member 'UAnimBP_UH60_C::TailIncidence0' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailIncidence1) == 0x002B94, "Member 'UAnimBP_UH60_C::TailIncidence1' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailIncidence2) == 0x002BA0, "Member 'UAnimBP_UH60_C::TailIncidence2' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailIncidence3) == 0x002BAC, "Member 'UAnimBP_UH60_C::TailIncidence3' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, RearTailRot) == 0x002BB8, "Member 'UAnimBP_UH60_C::RearTailRot' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, ControlStickRot) == 0x002BC4, "Member 'UAnimBP_UH60_C::ControlStickRot' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainBladesBlurScale) == 0x002BD0, "Member 'UAnimBP_UH60_C::MainBladesBlurScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainBladesScale) == 0x002BDC, "Member 'UAnimBP_UH60_C::MainBladesScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailBladesBlurScale) == 0x002BE8, "Member 'UAnimBP_UH60_C::TailBladesBlurScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailBladesScale) == 0x002BF4, "Member 'UAnimBP_UH60_C::TailBladesScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, MainRotorScale) == 0x002C00, "Member 'UAnimBP_UH60_C::MainRotorScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_UH60_C, TailRotorScale) == 0x002C0C, "Member 'UAnimBP_UH60_C::TailRotorScale' has a wrong offset!");

}

