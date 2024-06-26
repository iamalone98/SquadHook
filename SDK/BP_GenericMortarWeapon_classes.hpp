#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericMortarWeapon

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericMortarWeapon.BP_GenericMortarWeapon_C
// 0x00A0 (0x0C40 - 0x0BA0)
class ABP_GenericMortarWeapon_C : public ASQVehicleWeapon
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0BA0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USceneComponent*                        Adscameraposition;                                 // 0x0BA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USpringArmComponent*                    SpringArm;                                         // 0x0BB0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQBlastComponent*                      SquadBlast;                                        // 0x0BB8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USoundCue*                              SoundTest;                                         // 0x0BC0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh1PReturnSection;                               // 0x0BC8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh3PReturnSection;                               // 0x0BD0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   SoldierMeshReturnSection;                          // 0x0BD8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   BackblastSocket;                                   // 0x0BE0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        BackblastEffect1P;                                 // 0x0BE8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        BackblastEffect3P;                                 // 0x0BF0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarFireSoldierAnimation;                        // 0x0BF8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarFireWeaponAnimation;                         // 0x0C00(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarReloadWeaponAnimation;                       // 0x0C08(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarReloadSoldierAnimation;                      // 0x0C10(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarReloadDryWeaponAnimation;                    // 0x0C18(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarReloadDrySoldierAnimation;                   // 0x0C20(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarDeployWeaponAnimation;                       // 0x0C28(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           MortarDeploySoldierAnimation;                      // 0x0C30(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 ReticleClass;                                      // 0x0C38(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericMortarWeapon(int32 EntryPoint);
	void BlueprintOnZoom(bool bNewZoom);
	void BlueprintOnFire(const struct FVector& Origin);
	void BlueprintOnReload();
	void SoldierEntersVehicle(class ASQSoldier* Soldier);
	void SoldierLeavesVehicle(class ASQSoldier* Soldier);
	void PlayAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, class ASQSoldier* Soldier, float* TripodAnimTime, float* WeaponAnimTime, float* SoldierAnimTime);
	void StopAnimations(class ASQSoldier* Soldier);
	void ResumeAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericMortarWeapon_C">();
	}
	static class ABP_GenericMortarWeapon_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericMortarWeapon_C>();
	}
};
static_assert(alignof(ABP_GenericMortarWeapon_C) == 0x000010, "Wrong alignment on ABP_GenericMortarWeapon_C");
static_assert(sizeof(ABP_GenericMortarWeapon_C) == 0x000C40, "Wrong size on ABP_GenericMortarWeapon_C");
static_assert(offsetof(ABP_GenericMortarWeapon_C, UberGraphFrame) == 0x000BA0, "Member 'ABP_GenericMortarWeapon_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, Adscameraposition) == 0x000BA8, "Member 'ABP_GenericMortarWeapon_C::Adscameraposition' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, SpringArm) == 0x000BB0, "Member 'ABP_GenericMortarWeapon_C::SpringArm' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, SquadBlast) == 0x000BB8, "Member 'ABP_GenericMortarWeapon_C::SquadBlast' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, SoundTest) == 0x000BC0, "Member 'ABP_GenericMortarWeapon_C::SoundTest' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, Mesh1PReturnSection) == 0x000BC8, "Member 'ABP_GenericMortarWeapon_C::Mesh1PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, Mesh3PReturnSection) == 0x000BD0, "Member 'ABP_GenericMortarWeapon_C::Mesh3PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, SoldierMeshReturnSection) == 0x000BD8, "Member 'ABP_GenericMortarWeapon_C::SoldierMeshReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, BackblastSocket) == 0x000BE0, "Member 'ABP_GenericMortarWeapon_C::BackblastSocket' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, BackblastEffect1P) == 0x000BE8, "Member 'ABP_GenericMortarWeapon_C::BackblastEffect1P' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, BackblastEffect3P) == 0x000BF0, "Member 'ABP_GenericMortarWeapon_C::BackblastEffect3P' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarFireSoldierAnimation) == 0x000BF8, "Member 'ABP_GenericMortarWeapon_C::MortarFireSoldierAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarFireWeaponAnimation) == 0x000C00, "Member 'ABP_GenericMortarWeapon_C::MortarFireWeaponAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarReloadWeaponAnimation) == 0x000C08, "Member 'ABP_GenericMortarWeapon_C::MortarReloadWeaponAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarReloadSoldierAnimation) == 0x000C10, "Member 'ABP_GenericMortarWeapon_C::MortarReloadSoldierAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarReloadDryWeaponAnimation) == 0x000C18, "Member 'ABP_GenericMortarWeapon_C::MortarReloadDryWeaponAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarReloadDrySoldierAnimation) == 0x000C20, "Member 'ABP_GenericMortarWeapon_C::MortarReloadDrySoldierAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarDeployWeaponAnimation) == 0x000C28, "Member 'ABP_GenericMortarWeapon_C::MortarDeployWeaponAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, MortarDeploySoldierAnimation) == 0x000C30, "Member 'ABP_GenericMortarWeapon_C::MortarDeploySoldierAnimation' has a wrong offset!");
static_assert(offsetof(ABP_GenericMortarWeapon_C, ReticleClass) == 0x000C38, "Member 'ABP_GenericMortarWeapon_C::ReticleClass' has a wrong offset!");

}

