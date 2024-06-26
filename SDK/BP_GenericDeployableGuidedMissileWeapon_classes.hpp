#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDeployableGuidedMissileWeapon

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C
// 0x0100 (0x0D10 - 0x0C10)
class ABP_GenericDeployableGuidedMissileWeapon_C : public ASQVehicleWeaponTOW
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0C10(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USoundCue*                              SoundTest;                                         // 0x0C18(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh1PReturnSection;                               // 0x0C20(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Mesh3PReturnSection;                               // 0x0C28(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   SoldierMeshReturnSection;                          // 0x0C30(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   BackblastSocket;                                   // 0x0C38(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 ReticleClass;                                      // 0x0C40(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterial*                              ReticlePPMat;                                      // 0x0C48(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQProjectileMovement*                  LaunchedProjMoveComp;                              // 0x0C50(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          IsADS;                                             // 0x0C58(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4E1A[0x3];                                     // 0x0C59(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         ZoomLevel;                                         // 0x0C5C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USoundBase*                             FireDelaySound;                                    // 0x0C60(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         FireDelayDuration;                                 // 0x0C68(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E1B[0x4];                                     // 0x0C6C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimMontage*                           Reload_Weapon_Animation;                           // 0x0C70(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Reload_Soldier_Animation;                          // 0x0C78(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Reload_Dry_Weapon_Animation;                       // 0x0C80(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Reload_Dry_Soldier_Animation;                      // 0x0C88(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Reload_Dry_Tripod_Animation;                       // 0x0C90(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Reload_Tripod_Animation;                           // 0x0C98(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Equip_Tripod_Animation;                            // 0x0CA0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Equip_Weapon_Animation;                            // 0x0CA8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Equip_Soldier_Animation;                           // 0x0CB0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Fire_Tripod_Animation;                             // 0x0CB8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Fire_Weapon_Animation;                             // 0x0CC0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Fire_Soldier_Animation;                            // 0x0CC8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQHUD*                                 Last_HUD;                                          // 0x0CD0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            BPLast_PC;                                         // 0x0CD8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MeshCurrentMontageTime;                            // 0x0CE0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E1C[0x4];                                     // 0x0CE4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimMontage*                           Equip_Transition_Tripod_Animation;                 // 0x0CE8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Equip_Transition_Weapon_Animation;                 // 0x0CF0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UAnimMontage*                           Equip_Transition_Soldier_Animation;                // 0x0CF8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           ReloadAnimTimer;                                   // 0x0D00(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericDeployableGuidedMissileWeapon(int32 EntryPoint);
	void FinishReloadAnim();
	void BlueprintOnUnequip();
	void CameraOnWeapon();
	void CameraOnSoldier();
	void BlueprintOnPreFire();
	void BlueprintOnEquip();
	void SoldierLeavesVehicle(class ASQSoldier* Soldier);
	void SoldierEntersVehicle(class ASQSoldier* Soldier);
	void BlueprintOnReload();
	void BlueprintOnFire(const struct FVector& Origin);
	void PlayAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, class ASQSoldier* Soldier, float* TripodAnimTime, float* WeaponAnimTime, float* SoldierAnimTime);
	void StopAnimations(class ASQSoldier* Soldier);
	void ResumeAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, float* AnimDuration);
	void SetReloadAnimTimer(float Time);
	struct FPostProcessSettings GetPostProcessSettings();
	TSubclassOf<class USQVehicleViewWidget> GetReticleClass();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericDeployableGuidedMissileWeapon_C">();
	}
	static class ABP_GenericDeployableGuidedMissileWeapon_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericDeployableGuidedMissileWeapon_C>();
	}
};
static_assert(alignof(ABP_GenericDeployableGuidedMissileWeapon_C) == 0x000010, "Wrong alignment on ABP_GenericDeployableGuidedMissileWeapon_C");
static_assert(sizeof(ABP_GenericDeployableGuidedMissileWeapon_C) == 0x000D10, "Wrong size on ABP_GenericDeployableGuidedMissileWeapon_C");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, UberGraphFrame) == 0x000C10, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, SoundTest) == 0x000C18, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::SoundTest' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Mesh1PReturnSection) == 0x000C20, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Mesh1PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Mesh3PReturnSection) == 0x000C28, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Mesh3PReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, SoldierMeshReturnSection) == 0x000C30, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::SoldierMeshReturnSection' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, BackblastSocket) == 0x000C38, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::BackblastSocket' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, ReticleClass) == 0x000C40, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::ReticleClass' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, ReticlePPMat) == 0x000C48, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::ReticlePPMat' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, LaunchedProjMoveComp) == 0x000C50, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::LaunchedProjMoveComp' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, IsADS) == 0x000C58, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::IsADS' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, ZoomLevel) == 0x000C5C, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::ZoomLevel' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, FireDelaySound) == 0x000C60, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::FireDelaySound' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, FireDelayDuration) == 0x000C68, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::FireDelayDuration' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Weapon_Animation) == 0x000C70, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Weapon_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Soldier_Animation) == 0x000C78, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Soldier_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Dry_Weapon_Animation) == 0x000C80, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Dry_Weapon_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Dry_Soldier_Animation) == 0x000C88, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Dry_Soldier_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Dry_Tripod_Animation) == 0x000C90, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Dry_Tripod_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Reload_Tripod_Animation) == 0x000C98, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Reload_Tripod_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Tripod_Animation) == 0x000CA0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Tripod_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Weapon_Animation) == 0x000CA8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Weapon_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Soldier_Animation) == 0x000CB0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Soldier_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Fire_Tripod_Animation) == 0x000CB8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Fire_Tripod_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Fire_Weapon_Animation) == 0x000CC0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Fire_Weapon_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Fire_Soldier_Animation) == 0x000CC8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Fire_Soldier_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Last_HUD) == 0x000CD0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Last_HUD' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, BPLast_PC) == 0x000CD8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::BPLast_PC' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, MeshCurrentMontageTime) == 0x000CE0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::MeshCurrentMontageTime' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Transition_Tripod_Animation) == 0x000CE8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Transition_Tripod_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Transition_Weapon_Animation) == 0x000CF0, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Transition_Weapon_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, Equip_Transition_Soldier_Animation) == 0x000CF8, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::Equip_Transition_Soldier_Animation' has a wrong offset!");
static_assert(offsetof(ABP_GenericDeployableGuidedMissileWeapon_C, ReloadAnimTimer) == 0x000D00, "Member 'ABP_GenericDeployableGuidedMissileWeapon_C::ReloadAnimTimer' has a wrong offset!");

}

