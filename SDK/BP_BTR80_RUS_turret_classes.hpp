#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BTR80_RUS_turret

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BTR80_RUS_turret.BP_BTR80_RUS_turret_C
// 0x0070 (0x04C0 - 0x0450)
#pragma pack(push, 0x1)
class alignas(0x10) ABP_BTR80_RUS_turret_C : public ASQVehicleTurretClosedTop
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0450(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQRotationMovementAudioComponent*      SQRotationMovementAudio;                           // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        GunAttachPoint;                                    // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USkeletalMeshComponent*                 BTR_82A_turret;                                    // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQTurretMovementComponent*             SQTurretMovement;                                  // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       FirstPersonCamera;                                 // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       Camera;                                            // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           SQVehicleInventory;                                // 0x0490(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0498(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         Timeline_0_lerp_748BAE154D2D3799118C13B46CAA6BB0;  // 0x04A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_0__Direction_748BAE154D2D3799118C13B46CAA6BB0; // 0x04A4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4E79[0x3];                                     // 0x04A5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_0;                                        // 0x04A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         KeyboardYawRotationMultiplier;                     // 0x04B0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         KeyboardPitchRotationMultiplier;                   // 0x04B4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_BTR80_RUS_turret(int32 EntryPoint);
	void InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2(float AxisValue);
	void InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0(float AxisValue);
	void BP_OnVehicleZoom();
	void ResetZoom();
	void ReceiveBeginPlay();
	void InpActEvt_Fire_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key);
	void Timeline_0__UpdateFunc();
	void Timeline_0__FinishedFunc();
	void UserConstructionScript();

	class USceneComponent* Get3PAttachComponent() const;
	class USceneComponent* Get1PAttachComponent() const;
	class USkinnedMeshComponent* GetMasterPoseComponent() const;
	class USceneComponent* GetWeaponAttachComponent() const;
	class USceneComponent* GetADSCameraLocationComponent() const;
	class USQTurretMovementComponent* GetTurretMovementComponent() const;
	class USceneComponent* GetSoldierAttachComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BTR80_RUS_turret_C">();
	}
	static class ABP_BTR80_RUS_turret_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BTR80_RUS_turret_C>();
	}
};
#pragma pack(pop)
static_assert(alignof(ABP_BTR80_RUS_turret_C) == 0x000010, "Wrong alignment on ABP_BTR80_RUS_turret_C");
static_assert(sizeof(ABP_BTR80_RUS_turret_C) == 0x0004C0, "Wrong size on ABP_BTR80_RUS_turret_C");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, UberGraphFrame) == 0x000450, "Member 'ABP_BTR80_RUS_turret_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, SQRotationMovementAudio) == 0x000458, "Member 'ABP_BTR80_RUS_turret_C::SQRotationMovementAudio' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, GunAttachPoint) == 0x000460, "Member 'ABP_BTR80_RUS_turret_C::GunAttachPoint' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, SQArmorMesh) == 0x000468, "Member 'ABP_BTR80_RUS_turret_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, BTR_82A_turret) == 0x000470, "Member 'ABP_BTR80_RUS_turret_C::BTR_82A_turret' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, SQTurretMovement) == 0x000478, "Member 'ABP_BTR80_RUS_turret_C::SQTurretMovement' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, FirstPersonCamera) == 0x000480, "Member 'ABP_BTR80_RUS_turret_C::FirstPersonCamera' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, Camera) == 0x000488, "Member 'ABP_BTR80_RUS_turret_C::Camera' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, SQVehicleInventory) == 0x000490, "Member 'ABP_BTR80_RUS_turret_C::SQVehicleInventory' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, DefaultSceneRoot) == 0x000498, "Member 'ABP_BTR80_RUS_turret_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, Timeline_0_lerp_748BAE154D2D3799118C13B46CAA6BB0) == 0x0004A0, "Member 'ABP_BTR80_RUS_turret_C::Timeline_0_lerp_748BAE154D2D3799118C13B46CAA6BB0' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, Timeline_0__Direction_748BAE154D2D3799118C13B46CAA6BB0) == 0x0004A4, "Member 'ABP_BTR80_RUS_turret_C::Timeline_0__Direction_748BAE154D2D3799118C13B46CAA6BB0' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, Timeline_0) == 0x0004A8, "Member 'ABP_BTR80_RUS_turret_C::Timeline_0' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, KeyboardYawRotationMultiplier) == 0x0004B0, "Member 'ABP_BTR80_RUS_turret_C::KeyboardYawRotationMultiplier' has a wrong offset!");
static_assert(offsetof(ABP_BTR80_RUS_turret_C, KeyboardPitchRotationMultiplier) == 0x0004B4, "Member 'ABP_BTR80_RUS_turret_C::KeyboardPitchRotationMultiplier' has a wrong offset!");

}

