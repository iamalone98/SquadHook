#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV4034_Commander_Periscope

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_FV4034_Commander_Periscope.BP_FV4034_Commander_Periscope_C
// 0x0060 (0x04B0 - 0x0450)
class ABP_FV4034_Commander_Periscope_C final : public ASQVehicleTurretClosedTop
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0450(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQTurretMovementComponent*             TurretMovement;                                    // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        GunAttachPoint;                                    // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       Camera;                                            // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       FirstPersonCamera;                                 // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        Scene;                                             // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USkeletalMeshComponent*                 Turret_SkeletalMesh;                               // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQRotationMovementAudioComponent*      SQRotationMovementAudio;                           // 0x0490(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           SQVehicleInventory;                                // 0x0498(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         Timeline_0_lerp_FA2E7AA749C2B93709CEDA8730C47B64;  // 0x04A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_0__Direction_FA2E7AA749C2B93709CEDA8730C47B64; // 0x04A4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4C50[0x3];                                     // 0x04A5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_0;                                        // 0x04A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_FV4034_Commander_Periscope(int32 EntryPoint);
	void ServerSetStabilizationHeading();
	void BP_OnVehicleZoom();
	void ResetZoom();
	void ReceiveBeginPlay();
	void InpActEvt_DesignateTarget_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key);
	void InpActEvt_Fire_K2Node_InputActionEvent_2(const struct FKey& Key);
	void Timeline_0__UpdateFunc();
	void Timeline_0__FinishedFunc();
	void UserConstructionScript();

	class USceneComponent* GetWeaponAttachComponent() const;
	class USceneComponent* Get3PAttachComponent() const;
	class USceneComponent* Get1PAttachComponent() const;
	class USkinnedMeshComponent* GetMasterPoseComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_FV4034_Commander_Periscope_C">();
	}
	static class ABP_FV4034_Commander_Periscope_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_FV4034_Commander_Periscope_C>();
	}
};
static_assert(alignof(ABP_FV4034_Commander_Periscope_C) == 0x000010, "Wrong alignment on ABP_FV4034_Commander_Periscope_C");
static_assert(sizeof(ABP_FV4034_Commander_Periscope_C) == 0x0004B0, "Wrong size on ABP_FV4034_Commander_Periscope_C");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, UberGraphFrame) == 0x000450, "Member 'ABP_FV4034_Commander_Periscope_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, SQArmorMesh) == 0x000458, "Member 'ABP_FV4034_Commander_Periscope_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, TurretMovement) == 0x000460, "Member 'ABP_FV4034_Commander_Periscope_C::TurretMovement' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, GunAttachPoint) == 0x000468, "Member 'ABP_FV4034_Commander_Periscope_C::GunAttachPoint' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Camera) == 0x000470, "Member 'ABP_FV4034_Commander_Periscope_C::Camera' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, FirstPersonCamera) == 0x000478, "Member 'ABP_FV4034_Commander_Periscope_C::FirstPersonCamera' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Scene) == 0x000480, "Member 'ABP_FV4034_Commander_Periscope_C::Scene' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Turret_SkeletalMesh) == 0x000488, "Member 'ABP_FV4034_Commander_Periscope_C::Turret_SkeletalMesh' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, SQRotationMovementAudio) == 0x000490, "Member 'ABP_FV4034_Commander_Periscope_C::SQRotationMovementAudio' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, SQVehicleInventory) == 0x000498, "Member 'ABP_FV4034_Commander_Periscope_C::SQVehicleInventory' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Timeline_0_lerp_FA2E7AA749C2B93709CEDA8730C47B64) == 0x0004A0, "Member 'ABP_FV4034_Commander_Periscope_C::Timeline_0_lerp_FA2E7AA749C2B93709CEDA8730C47B64' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Timeline_0__Direction_FA2E7AA749C2B93709CEDA8730C47B64) == 0x0004A4, "Member 'ABP_FV4034_Commander_Periscope_C::Timeline_0__Direction_FA2E7AA749C2B93709CEDA8730C47B64' has a wrong offset!");
static_assert(offsetof(ABP_FV4034_Commander_Periscope_C, Timeline_0) == 0x0004A8, "Member 'ABP_FV4034_Commander_Periscope_C::Timeline_0' has a wrong offset!");

}

