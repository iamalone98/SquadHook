#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Emplaced_HellCannon_Base

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_GenericDeployableTripodVehicle_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Emplaced_HellCannon_Base.BP_Emplaced_HellCannon_Base_C
// 0x0030 (0x0A00 - 0x09D0)
class ABP_Emplaced_HellCannon_Base_C final : public ABP_GenericDeployableTripodVehicle_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Emplaced_HellCannon_Base_C;      // 0x09D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQArmorMeshComponent*                  SQArmorMeshGun;                                    // 0x09D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x09E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           VehicleExitPoint2;                                 // 0x09E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class AController*                            PlayerControllerRef;                               // 0x09F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 TurretOverlay;                                     // 0x09F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Emplaced_HellCannon_Base(int32 EntryPoint);
	void TurnOffDecimalBearing(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat);
	void TurnOnDecimalBearing(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat);
	void ReceiveUnpossessed(class AController* OldController);
	void ReceivePossessed(class AController* NewController);
	void InpActEvt_Focus_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_Focus_K2Node_InputActionEvent_1(const struct FKey& Key);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Emplaced_HellCannon_Base_C">();
	}
	static class ABP_Emplaced_HellCannon_Base_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Emplaced_HellCannon_Base_C>();
	}
};
static_assert(alignof(ABP_Emplaced_HellCannon_Base_C) == 0x000010, "Wrong alignment on ABP_Emplaced_HellCannon_Base_C");
static_assert(sizeof(ABP_Emplaced_HellCannon_Base_C) == 0x000A00, "Wrong size on ABP_Emplaced_HellCannon_Base_C");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, UberGraphFrame_BP_Emplaced_HellCannon_Base_C) == 0x0009D0, "Member 'ABP_Emplaced_HellCannon_Base_C::UberGraphFrame_BP_Emplaced_HellCannon_Base_C' has a wrong offset!");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, SQArmorMeshGun) == 0x0009D8, "Member 'ABP_Emplaced_HellCannon_Base_C::SQArmorMeshGun' has a wrong offset!");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, SQArmorMesh) == 0x0009E0, "Member 'ABP_Emplaced_HellCannon_Base_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, VehicleExitPoint2) == 0x0009E8, "Member 'ABP_Emplaced_HellCannon_Base_C::VehicleExitPoint2' has a wrong offset!");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, PlayerControllerRef) == 0x0009F0, "Member 'ABP_Emplaced_HellCannon_Base_C::PlayerControllerRef' has a wrong offset!");
static_assert(offsetof(ABP_Emplaced_HellCannon_Base_C, TurretOverlay) == 0x0009F8, "Member 'ABP_Emplaced_HellCannon_Base_C::TurretOverlay' has a wrong offset!");

}
