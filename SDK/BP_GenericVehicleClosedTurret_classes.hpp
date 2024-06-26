#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericVehicleClosedTurret

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericVehicleClosedTurret.BP_GenericVehicleClosedTurret_C
// 0x0080 (0x04D0 - 0x0450)
class ABP_GenericVehicleClosedTurret_C : public ASQVehicleTurretClosedTop
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0450(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBP_TurretTankNameGenerator_C*          SQTurretTankNameGenerator;                         // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQTurretMovementComponent*             TurretMovement;                                    // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   GunCollisionMesh;                                  // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USkeletalMeshComponent*                 SkeletalMesh;                                      // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQRotationMovementAudioComponent*      SQRotationMovementAudio;                           // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       FirstPersonCamera;                                 // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       Camera;                                            // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        GunAttachPoint;                                    // 0x0490(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USkeletalMeshComponent*                 Turret_SkeletalMesh;                               // 0x0498(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           SQVehicleInventory;                                // 0x04A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x04A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         Timeline_0_lerp_CEC9EA414025A28F160BC981592258A4;  // 0x04B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_0__Direction_CEC9EA414025A28F160BC981592258A4; // 0x04B4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3AC8[0x3];                                     // 0x04B5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_0;                                        // 0x04B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxRotationSpeed;                                  // 0x04C0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         RotationSpeedMultiplier;                           // 0x04C4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         ElevationSpeedMultiplier;                          // 0x04C8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         MaxElevationSpeed;                                 // 0x04CC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericVehicleClosedTurret(int32 EntryPoint);
	void BP_OnVehicleZoom();
	void ResetZoom();
	void ReceiveBeginPlay();
	void InpActEvt_Fire_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key);
	void Timeline_0__UpdateFunc();
	void Timeline_0__FinishedFunc();
	void UserConstructionScript();
	void EnsureMovementSettings();
	void CheckNetworkSettingsAreDefault(class USQVelocityRotatingMovementComponent* NewParam);

	class USceneComponent* Get3PAttachComponent() const;
	class USceneComponent* Get1PAttachComponent() const;
	class USkinnedMeshComponent* GetMasterPoseComponent() const;
	class USceneComponent* GetWeaponAttachComponent() const;
	class USceneComponent* GetADSCameraLocationComponent() const;
	class USceneComponent* GetSoldierAttachComponent() const;
	class USQTurretMovementComponent* GetTurretMovementComponent() const;
	class UCameraComponent* GetCameraComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericVehicleClosedTurret_C">();
	}
	static class ABP_GenericVehicleClosedTurret_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericVehicleClosedTurret_C>();
	}
};
static_assert(alignof(ABP_GenericVehicleClosedTurret_C) == 0x000010, "Wrong alignment on ABP_GenericVehicleClosedTurret_C");
static_assert(sizeof(ABP_GenericVehicleClosedTurret_C) == 0x0004D0, "Wrong size on ABP_GenericVehicleClosedTurret_C");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, UberGraphFrame) == 0x000450, "Member 'ABP_GenericVehicleClosedTurret_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, SQTurretTankNameGenerator) == 0x000458, "Member 'ABP_GenericVehicleClosedTurret_C::SQTurretTankNameGenerator' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, TurretMovement) == 0x000460, "Member 'ABP_GenericVehicleClosedTurret_C::TurretMovement' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, GunCollisionMesh) == 0x000468, "Member 'ABP_GenericVehicleClosedTurret_C::GunCollisionMesh' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, SkeletalMesh) == 0x000470, "Member 'ABP_GenericVehicleClosedTurret_C::SkeletalMesh' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, SQRotationMovementAudio) == 0x000478, "Member 'ABP_GenericVehicleClosedTurret_C::SQRotationMovementAudio' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, FirstPersonCamera) == 0x000480, "Member 'ABP_GenericVehicleClosedTurret_C::FirstPersonCamera' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, Camera) == 0x000488, "Member 'ABP_GenericVehicleClosedTurret_C::Camera' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, GunAttachPoint) == 0x000490, "Member 'ABP_GenericVehicleClosedTurret_C::GunAttachPoint' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, Turret_SkeletalMesh) == 0x000498, "Member 'ABP_GenericVehicleClosedTurret_C::Turret_SkeletalMesh' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, SQVehicleInventory) == 0x0004A0, "Member 'ABP_GenericVehicleClosedTurret_C::SQVehicleInventory' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, DefaultSceneRoot) == 0x0004A8, "Member 'ABP_GenericVehicleClosedTurret_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, Timeline_0_lerp_CEC9EA414025A28F160BC981592258A4) == 0x0004B0, "Member 'ABP_GenericVehicleClosedTurret_C::Timeline_0_lerp_CEC9EA414025A28F160BC981592258A4' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, Timeline_0__Direction_CEC9EA414025A28F160BC981592258A4) == 0x0004B4, "Member 'ABP_GenericVehicleClosedTurret_C::Timeline_0__Direction_CEC9EA414025A28F160BC981592258A4' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, Timeline_0) == 0x0004B8, "Member 'ABP_GenericVehicleClosedTurret_C::Timeline_0' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, MaxRotationSpeed) == 0x0004C0, "Member 'ABP_GenericVehicleClosedTurret_C::MaxRotationSpeed' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, RotationSpeedMultiplier) == 0x0004C4, "Member 'ABP_GenericVehicleClosedTurret_C::RotationSpeedMultiplier' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, ElevationSpeedMultiplier) == 0x0004C8, "Member 'ABP_GenericVehicleClosedTurret_C::ElevationSpeedMultiplier' has a wrong offset!");
static_assert(offsetof(ABP_GenericVehicleClosedTurret_C, MaxElevationSpeed) == 0x0004CC, "Member 'ABP_GenericVehicleClosedTurret_C::MaxElevationSpeed' has a wrong offset!");

}

