#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Technical_Turret_UB32

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Technical_Turret_UB32.BP_Technical_Turret_UB32_C
// 0x0080 (0x0450 - 0x03D0)
class ABP_Technical_Turret_UB32_C final : public ASQVehicleSeat
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x03D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x03D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQTurretMovementComponent*             SQTurretMovement;                                  // 0x03E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       Camera1pComponent;                                 // 0x03E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        AdsCamera1pPositionComponent;                      // 0x03F0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        Camera1pPositionComponent;                         // 0x03F8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQRotationMovementAudioComponent*      SQRotationMovementAudio;                           // 0x0400(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   UBMinus32_mount;                                   // 0x0408(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        GunMountComponent;                                 // 0x0410(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USkeletalMeshComponent*                 Turret_SkeletalMesh;                               // 0x0418(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           SQVehicleInventory;                                // 0x0420(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0428(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 TurretOverlay;                                     // 0x0430(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            PlayerControllerRef;                               // 0x0438(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ResetOrientationPitch;                             // 0x0440(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          ResetOrientationYaw;                               // 0x0441(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_4C05[0x2];                                     // 0x0442(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         KeyboardPitchRotationMultiplier;                   // 0x0444(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         KeyboardYawRotationMultiplier;                     // 0x0448(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Technical_Turret_UB32(int32 EntryPoint);
	void ReceiveUnpossessed(class AController* OldController);
	void ReceivePossessed(class AController* NewController);
	void InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_61(float AxisValue);
	void InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_57(float AxisValue);
	void InpAxisEvt_LookUp_K2Node_InputAxisEvent_42(float AxisValue);
	void InpAxisEvt_Turn_K2Node_InputAxisEvent_39(float AxisValue);
	void InpActEvt_Fire_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key);
	void UserConstructionScript();
	bool IsSoldierAlive();
	void IsCurrentWeaponInputEnabled(bool* bInputEnabled);

	class USceneComponent* Get3PAttachComponent() const;
	class USceneComponent* Get1PAttachComponent() const;
	class USkinnedMeshComponent* GetMasterPoseComponent() const;
	class USceneComponent* GetWeaponAttachComponent() const;
	class USceneComponent* GetSoldierAttachComponent() const;
	class USceneComponent* GetDefaultCameraLocationComponent() const;
	class USceneComponent* GetADSCameraLocationComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Technical_Turret_UB32_C">();
	}
	static class ABP_Technical_Turret_UB32_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Technical_Turret_UB32_C>();
	}
};
static_assert(alignof(ABP_Technical_Turret_UB32_C) == 0x000010, "Wrong alignment on ABP_Technical_Turret_UB32_C");
static_assert(sizeof(ABP_Technical_Turret_UB32_C) == 0x000450, "Wrong size on ABP_Technical_Turret_UB32_C");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, UberGraphFrame) == 0x0003D0, "Member 'ABP_Technical_Turret_UB32_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, SQArmorMesh) == 0x0003D8, "Member 'ABP_Technical_Turret_UB32_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, SQTurretMovement) == 0x0003E0, "Member 'ABP_Technical_Turret_UB32_C::SQTurretMovement' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, Camera1pComponent) == 0x0003E8, "Member 'ABP_Technical_Turret_UB32_C::Camera1pComponent' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, AdsCamera1pPositionComponent) == 0x0003F0, "Member 'ABP_Technical_Turret_UB32_C::AdsCamera1pPositionComponent' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, Camera1pPositionComponent) == 0x0003F8, "Member 'ABP_Technical_Turret_UB32_C::Camera1pPositionComponent' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, SQRotationMovementAudio) == 0x000400, "Member 'ABP_Technical_Turret_UB32_C::SQRotationMovementAudio' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, UBMinus32_mount) == 0x000408, "Member 'ABP_Technical_Turret_UB32_C::UBMinus32_mount' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, GunMountComponent) == 0x000410, "Member 'ABP_Technical_Turret_UB32_C::GunMountComponent' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, Turret_SkeletalMesh) == 0x000418, "Member 'ABP_Technical_Turret_UB32_C::Turret_SkeletalMesh' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, SQVehicleInventory) == 0x000420, "Member 'ABP_Technical_Turret_UB32_C::SQVehicleInventory' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, DefaultSceneRoot) == 0x000428, "Member 'ABP_Technical_Turret_UB32_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, TurretOverlay) == 0x000430, "Member 'ABP_Technical_Turret_UB32_C::TurretOverlay' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, PlayerControllerRef) == 0x000438, "Member 'ABP_Technical_Turret_UB32_C::PlayerControllerRef' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, ResetOrientationPitch) == 0x000440, "Member 'ABP_Technical_Turret_UB32_C::ResetOrientationPitch' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, ResetOrientationYaw) == 0x000441, "Member 'ABP_Technical_Turret_UB32_C::ResetOrientationYaw' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, KeyboardPitchRotationMultiplier) == 0x000444, "Member 'ABP_Technical_Turret_UB32_C::KeyboardPitchRotationMultiplier' has a wrong offset!");
static_assert(offsetof(ABP_Technical_Turret_UB32_C, KeyboardYawRotationMultiplier) == 0x000448, "Member 'ABP_Technical_Turret_UB32_C::KeyboardYawRotationMultiplier' has a wrong offset!");

}
