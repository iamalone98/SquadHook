#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: AnimBP_SA330

#include "Basic.hpp"

#include "AnimGraphRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// AnimBlueprintGeneratedClass AnimBP_SA330.AnimBP_SA330_C
// 0x38A0 (0x4350 - 0x0AB0)
class UAnimBP_SA330_C final : public USQVehicleAnimInstance
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0AB0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_48;                       // 0x0AB8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_47;                       // 0x0BC0(0x0108)()
	struct FAnimNode_ConvertComponentToLocalSpace AnimGraphNode_ComponentToLocalSpace;               // 0x0CC8(0x0020)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_46;                       // 0x0CE8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_45;                       // 0x0DF0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_44;                       // 0x0EF8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_43;                       // 0x1000(0x0108)()
	struct FAnimNode_SaveCachedPose               AnimGraphNode_SaveCachedPose;                      // 0x1108(0x0158)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_42;                       // 0x1260(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_41;                       // 0x1368(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_40;                       // 0x1470(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_39;                       // 0x1578(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_38;                       // 0x1680(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_37;                       // 0x1788(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_36;                       // 0x1890(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_35;                       // 0x1998(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_34;                       // 0x1AA0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_33;                       // 0x1BA8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_32;                       // 0x1CB0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_31;                       // 0x1DB8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_30;                       // 0x1EC0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_29;                       // 0x1FC8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_28;                       // 0x20D0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_27;                       // 0x21D8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_26;                       // 0x22E0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_25;                       // 0x23E8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_24;                       // 0x24F0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_23;                       // 0x25F8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_22;                       // 0x2700(0x0108)()
	struct FAnimNode_Root                         AnimGraphNode_Root;                                // 0x2808(0x0030)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose_1;                     // 0x2838(0x0028)()
	struct FAnimNode_UseCachedPose                AnimGraphNode_UseCachedPose;                       // 0x2860(0x0028)()
	struct FAnimNode_LayeredBoneBlend             AnimGraphNode_LayeredBoneBlend;                    // 0x2888(0x00C0)()
	struct FAnimNode_Slot                         AnimGraphNode_Slot;                                // 0x2948(0x0048)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_21;                       // 0x2990(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_20;                       // 0x2A98(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_19;                       // 0x2BA0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_18;                       // 0x2CA8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_17;                       // 0x2DB0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_16;                       // 0x2EB8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_15;                       // 0x2FC0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_14;                       // 0x30C8(0x0108)()
	struct FAnimNode_TwoWayBlend                  AnimGraphNode_TwoWayBlend;                         // 0x31D0(0x00C8)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_13;                       // 0x3298(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_12;                       // 0x33A0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_11;                       // 0x34A8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_10;                       // 0x35B0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_9;                        // 0x36B8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_8;                        // 0x37C0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_7;                        // 0x38C8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_6;                        // 0x39D0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_5;                        // 0x3AD8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_4;                        // 0x3BE0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_3;                        // 0x3CE8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_2;                        // 0x3DF0(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone_1;                        // 0x3EF8(0x0108)()
	struct FAnimNode_ModifyBone                   AnimGraphNode_ModifyBone;                          // 0x4000(0x0108)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer_1;                    // 0x4108(0x0080)()
	struct FAnimNode_ConvertLocalToComponentSpace AnimGraphNode_LocalToComponentSpace;               // 0x4188(0x0020)()
	struct FAnimNode_SequencePlayer               AnimGraphNode_SequencePlayer;                      // 0x41A8(0x0080)()
	struct FVector                                Wheel_Front_Scale;                                 // 0x4228(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                Wheel_Rear_L_Scale;                                // 0x4234(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                Wheel_Rear_R_Scale;                                // 0x4240(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               MainIncidence0;                                    // 0x424C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence3;                                    // 0x4258(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence1;                                    // 0x4264(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence2;                                    // 0x4270(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence0;                                    // 0x427C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence1;                                    // 0x4288(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence2;                                    // 0x4294(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainIncidence4;                                    // 0x42A0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence3;                                    // 0x42AC(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailRotorRotation;                                 // 0x42B8(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               MainRotorRotation;                                 // 0x42C4(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FVector                                MainBladesScale;                                   // 0x42D0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                MainBladesBlurScale;                               // 0x42DC(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailBladesScale;                                   // 0x42E8(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailBladesBlurScale;                               // 0x42F4(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         BladesLiftAlpha;                                   // 0x4300(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxLiftDegrees;                                    // 0x4304(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               RearTailRot;                                       // 0x4308(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               ControlStickRot;                                   // 0x4314(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FRotator                               TailIncidence4;                                    // 0x4320(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FVector                                MainBlades_DestroyScale;                           // 0x432C(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                TailBlades_DestroyScale;                           // 0x4338(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         LandedAlpha;                                       // 0x4344(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_AnimBP_SA330(int32 EntryPoint);
	void BlueprintUpdateAnimation(float DeltaTimeX);
	void GetBladesScale(class ABP_SA330_C* Helicopter, bool Main, struct FVector* Blades, struct FVector* BlurBlades);
	void GerCurrentRotorRPM(class ABP_SA330_C* Helicopter, bool Main, float* RPM);
	void RPMtoDegPerSec(float RPM, class ABP_SA330_C* Helicopter, bool Main, float* DegPerSec);
	void AnimGraph(struct FPoseLink* Param_AnimGraph);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"AnimBP_SA330_C">();
	}
	static class UAnimBP_SA330_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UAnimBP_SA330_C>();
	}
};
static_assert(alignof(UAnimBP_SA330_C) == 0x000010, "Wrong alignment on UAnimBP_SA330_C");
static_assert(sizeof(UAnimBP_SA330_C) == 0x004350, "Wrong size on UAnimBP_SA330_C");
static_assert(offsetof(UAnimBP_SA330_C, UberGraphFrame) == 0x000AB0, "Member 'UAnimBP_SA330_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_48) == 0x000AB8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_48' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_47) == 0x000BC0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_47' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ComponentToLocalSpace) == 0x000CC8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ComponentToLocalSpace' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_46) == 0x000CE8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_46' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_45) == 0x000DF0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_45' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_44) == 0x000EF8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_44' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_43) == 0x001000, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_43' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_SaveCachedPose) == 0x001108, "Member 'UAnimBP_SA330_C::AnimGraphNode_SaveCachedPose' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_42) == 0x001260, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_42' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_41) == 0x001368, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_41' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_40) == 0x001470, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_40' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_39) == 0x001578, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_39' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_38) == 0x001680, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_38' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_37) == 0x001788, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_37' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_36) == 0x001890, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_36' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_35) == 0x001998, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_35' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_34) == 0x001AA0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_34' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_33) == 0x001BA8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_33' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_32) == 0x001CB0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_32' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_31) == 0x001DB8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_31' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_30) == 0x001EC0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_30' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_29) == 0x001FC8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_29' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_28) == 0x0020D0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_28' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_27) == 0x0021D8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_27' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_26) == 0x0022E0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_26' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_25) == 0x0023E8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_25' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_24) == 0x0024F0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_24' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_23) == 0x0025F8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_23' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_22) == 0x002700, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_22' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_Root) == 0x002808, "Member 'UAnimBP_SA330_C::AnimGraphNode_Root' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_UseCachedPose_1) == 0x002838, "Member 'UAnimBP_SA330_C::AnimGraphNode_UseCachedPose_1' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_UseCachedPose) == 0x002860, "Member 'UAnimBP_SA330_C::AnimGraphNode_UseCachedPose' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_LayeredBoneBlend) == 0x002888, "Member 'UAnimBP_SA330_C::AnimGraphNode_LayeredBoneBlend' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_Slot) == 0x002948, "Member 'UAnimBP_SA330_C::AnimGraphNode_Slot' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_21) == 0x002990, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_21' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_20) == 0x002A98, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_20' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_19) == 0x002BA0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_19' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_18) == 0x002CA8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_18' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_17) == 0x002DB0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_17' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_16) == 0x002EB8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_16' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_15) == 0x002FC0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_15' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_14) == 0x0030C8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_14' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_TwoWayBlend) == 0x0031D0, "Member 'UAnimBP_SA330_C::AnimGraphNode_TwoWayBlend' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_13) == 0x003298, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_13' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_12) == 0x0033A0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_12' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_11) == 0x0034A8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_11' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_10) == 0x0035B0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_10' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_9) == 0x0036B8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_9' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_8) == 0x0037C0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_8' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_7) == 0x0038C8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_7' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_6) == 0x0039D0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_6' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_5) == 0x003AD8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_5' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_4) == 0x003BE0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_4' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_3) == 0x003CE8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_3' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_2) == 0x003DF0, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_2' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone_1) == 0x003EF8, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone_1' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_ModifyBone) == 0x004000, "Member 'UAnimBP_SA330_C::AnimGraphNode_ModifyBone' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_SequencePlayer_1) == 0x004108, "Member 'UAnimBP_SA330_C::AnimGraphNode_SequencePlayer_1' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_LocalToComponentSpace) == 0x004188, "Member 'UAnimBP_SA330_C::AnimGraphNode_LocalToComponentSpace' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, AnimGraphNode_SequencePlayer) == 0x0041A8, "Member 'UAnimBP_SA330_C::AnimGraphNode_SequencePlayer' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, Wheel_Front_Scale) == 0x004228, "Member 'UAnimBP_SA330_C::Wheel_Front_Scale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, Wheel_Rear_L_Scale) == 0x004234, "Member 'UAnimBP_SA330_C::Wheel_Rear_L_Scale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, Wheel_Rear_R_Scale) == 0x004240, "Member 'UAnimBP_SA330_C::Wheel_Rear_R_Scale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainIncidence0) == 0x00424C, "Member 'UAnimBP_SA330_C::MainIncidence0' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainIncidence3) == 0x004258, "Member 'UAnimBP_SA330_C::MainIncidence3' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainIncidence1) == 0x004264, "Member 'UAnimBP_SA330_C::MainIncidence1' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainIncidence2) == 0x004270, "Member 'UAnimBP_SA330_C::MainIncidence2' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailIncidence0) == 0x00427C, "Member 'UAnimBP_SA330_C::TailIncidence0' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailIncidence1) == 0x004288, "Member 'UAnimBP_SA330_C::TailIncidence1' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailIncidence2) == 0x004294, "Member 'UAnimBP_SA330_C::TailIncidence2' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainIncidence4) == 0x0042A0, "Member 'UAnimBP_SA330_C::MainIncidence4' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailIncidence3) == 0x0042AC, "Member 'UAnimBP_SA330_C::TailIncidence3' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailRotorRotation) == 0x0042B8, "Member 'UAnimBP_SA330_C::TailRotorRotation' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainRotorRotation) == 0x0042C4, "Member 'UAnimBP_SA330_C::MainRotorRotation' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainBladesScale) == 0x0042D0, "Member 'UAnimBP_SA330_C::MainBladesScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainBladesBlurScale) == 0x0042DC, "Member 'UAnimBP_SA330_C::MainBladesBlurScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailBladesScale) == 0x0042E8, "Member 'UAnimBP_SA330_C::TailBladesScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailBladesBlurScale) == 0x0042F4, "Member 'UAnimBP_SA330_C::TailBladesBlurScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, BladesLiftAlpha) == 0x004300, "Member 'UAnimBP_SA330_C::BladesLiftAlpha' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MaxLiftDegrees) == 0x004304, "Member 'UAnimBP_SA330_C::MaxLiftDegrees' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, RearTailRot) == 0x004308, "Member 'UAnimBP_SA330_C::RearTailRot' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, ControlStickRot) == 0x004314, "Member 'UAnimBP_SA330_C::ControlStickRot' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailIncidence4) == 0x004320, "Member 'UAnimBP_SA330_C::TailIncidence4' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, MainBlades_DestroyScale) == 0x00432C, "Member 'UAnimBP_SA330_C::MainBlades_DestroyScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, TailBlades_DestroyScale) == 0x004338, "Member 'UAnimBP_SA330_C::TailBlades_DestroyScale' has a wrong offset!");
static_assert(offsetof(UAnimBP_SA330_C, LandedAlpha) == 0x004344, "Member 'UAnimBP_SA330_C::LandedAlpha' has a wrong offset!");

}

