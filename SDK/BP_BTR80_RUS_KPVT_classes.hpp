#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BTR80_RUS_KPVT

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BTR80_RUS_KPVT.BP_BTR80_RUS_KPVT_C
// 0x0070 (0x0C10 - 0x0BA0)
class ABP_BTR80_RUS_KPVT_C : public ASQVehicleWeapon
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0BA0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQTemperatureComponent*                SQTemperature;                                     // 0x0BA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         ShutdownTemp;                                      // 0x0BB0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OverheatEffectTrigger_1;                           // 0x0BB4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OverheatEffectTrigger_2;                           // 0x0BB8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_271E[0x4];                                     // 0x0BBC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UParticleSystemComponent*               Overheat_1_Effect;                                 // 0x0BC0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Overheat_2_Effect;                                 // 0x0BC8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Overheat_3_Effect;                                 // 0x0BD0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        Overheat_1_Sound;                                  // 0x0BD8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        Overheat_2_Sound;                                  // 0x0BE0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USoundCue*                              SoundTest;                                         // 0x0BE8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        Overheat_3_Sound;                                  // 0x0BF0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh1PReturnSection;                               // 0x0BF8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh3PReturnSection;                               // 0x0C00(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   SoldierMeshReturnSection;                          // 0x0C08(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_BTR80_RUS_KPVT(int32 EntryPoint);
	void SoldierLeavesVehicle(class ASQSoldier* Soldier);
	void SoldierEntersVehicle(class ASQSoldier* Soldier);
	void BlueprintOnReload();
	void BlueprintOnFire(const struct FVector& Origin);
	void BndEvt__SQTemperature_K2Node_ComponentBoundEvent_486_TemperatureIncrementDelegate__DelegateSignature(class USQTemperatureComponent* TriggeringComponent, float TriggeringTemp, bool bIsLowerTrigger);
	void PlayAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, class ASQSoldier* Soldier, float* TripodAnimTime, float* WeaponAnimTime, float* SoldierAnimTime);
	void StopAnimations(class ASQSoldier* Soldier);
	void ResumeAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BTR80_RUS_KPVT_C">();
	}
	static class ABP_BTR80_RUS_KPVT_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BTR80_RUS_KPVT_C>();
	}
};
static_assert(alignof(ABP_BTR80_RUS_KPVT_C) == 0x000010, "Wrong alignment on ABP_BTR80_RUS_KPVT_C");
static_assert(sizeof(ABP_BTR80_RUS_KPVT_C) == 0x000C10, "Wrong size on ABP_BTR80_RUS_KPVT_C");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, UberGraphFrame) == 0x000BA0, "Member 'ABP_BTR80_RUS_KPVT_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, SQTemperature) == 0x000BA8, "Member 'ABP_BTR80_RUS_KPVT_C::SQTemperature' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, ShutdownTemp) == 0x000BB0, "Member 'ABP_BTR80_RUS_KPVT_C::ShutdownTemp' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, OverheatEffectTrigger_1) == 0x000BB4, "Member 'ABP_BTR80_RUS_KPVT_C::OverheatEffectTrigger_1' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, OverheatEffectTrigger_2) == 0x000BB8, "Member 'ABP_BTR80_RUS_KPVT_C::OverheatEffectTrigger_2' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_1_Effect) == 0x000BC0, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_1_Effect' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_2_Effect) == 0x000BC8, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_2_Effect' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_3_Effect) == 0x000BD0, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_3_Effect' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_1_Sound) == 0x000BD8, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_1_Sound' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_2_Sound) == 0x000BE0, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_2_Sound' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, SoundTest) == 0x000BE8, "Member 'ABP_BTR80_RUS_KPVT_C::SoundTest' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Overheat_3_Sound) == 0x000BF0, "Member 'ABP_BTR80_RUS_KPVT_C::Overheat_3_Sound' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Mesh1PReturnSection) == 0x000BF8, "Member 'ABP_BTR80_RUS_KPVT_C::Mesh1PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, Mesh3PReturnSection) == 0x000C00, "Member 'ABP_BTR80_RUS_KPVT_C::Mesh3PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_KPVT_C, SoldierMeshReturnSection) == 0x000C08, "Member 'ABP_BTR80_RUS_KPVT_C::SoldierMeshReturnSection' has a wrong offset!");

}

