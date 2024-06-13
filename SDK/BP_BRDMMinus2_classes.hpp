#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BRDMMinus2

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BRDM-2.BP_BRDM-2_C
// 0x00B0 (0x0C10 - 0x0B60)
class ABP_BRDMMinus2_C : public ASQWheeledVehicle
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0B60(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQVehicleExitPointComponent*           SQWaterExitPoint;                                  // 0x0B68(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQWaterThrusterComponent*              SQWaterThruster;                                   // 0x0B70(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMeshWaterShield;                            // 0x0B78(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMeshDriverFlap;                             // 0x0B80(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0B88(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UChildActorComponent*                   CommandZone;                                       // 0x0B90(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   NoPenetrationBlock;                                // 0x0B98(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBPComponent_RadialModel_C*             Vehicle_Radial;                                    // 0x0BA0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_R2;                                          // 0x0BA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_L2;                                          // 0x0BB0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_R1;                                          // 0x0BB8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_L1;                                          // 0x0BC0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   HullDecoration;                                    // 0x0BC8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleEngine*                       EngineComponent;                                   // 0x0BD0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleResourceWeaponInventoryComponent* SQVehicleResourceWeaponInventory;                  // 0x0BD8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQMapIconComponent*                    SQMapIcon;                                         // 0x0BE0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleBurningComponent*             SQVehicleBurning;                                  // 0x0BE8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint1;                               // 0x0BF0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint;                                // 0x0BF8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USoundBase*                             WheelDestroyedSound;                               // 0x0C00(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        WheelDestroyedEffect;                              // 0x0C08(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_BRDMMinus2(int32 EntryPoint);
	void DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent);
	void DrivetrainComponentRepaired(class USQDriveTrainComponent* DriveTrainComponent);
	void Update_Damaged_Wheel_Visual(class FName Bone, bool Destroyed, class USQVehicleWheel* Wheel, bool Do_Effects);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BRDM-2_C">();
	}
	static class ABP_BRDMMinus2_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BRDMMinus2_C>();
	}
};
static_assert(alignof(ABP_BRDMMinus2_C) == 0x000010, "Wrong alignment on ABP_BRDMMinus2_C");
static_assert(sizeof(ABP_BRDMMinus2_C) == 0x000C10, "Wrong size on ABP_BRDMMinus2_C");
static_assert(offsetof(ABP_BRDMMinus2_C, UberGraphFrame) == 0x000B60, "Member 'ABP_BRDMMinus2_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQWaterExitPoint) == 0x000B68, "Member 'ABP_BRDMMinus2_C::SQWaterExitPoint' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQWaterThruster) == 0x000B70, "Member 'ABP_BRDMMinus2_C::SQWaterThruster' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQArmorMeshWaterShield) == 0x000B78, "Member 'ABP_BRDMMinus2_C::SQArmorMeshWaterShield' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQArmorMeshDriverFlap) == 0x000B80, "Member 'ABP_BRDMMinus2_C::SQArmorMeshDriverFlap' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQArmorMesh) == 0x000B88, "Member 'ABP_BRDMMinus2_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, CommandZone) == 0x000B90, "Member 'ABP_BRDMMinus2_C::CommandZone' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, NoPenetrationBlock) == 0x000B98, "Member 'ABP_BRDMMinus2_C::NoPenetrationBlock' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, Vehicle_Radial) == 0x000BA0, "Member 'ABP_BRDMMinus2_C::Vehicle_Radial' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, Wheel_R2) == 0x000BA8, "Member 'ABP_BRDMMinus2_C::Wheel_R2' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, Wheel_L2) == 0x000BB0, "Member 'ABP_BRDMMinus2_C::Wheel_L2' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, Wheel_R1) == 0x000BB8, "Member 'ABP_BRDMMinus2_C::Wheel_R1' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, Wheel_L1) == 0x000BC0, "Member 'ABP_BRDMMinus2_C::Wheel_L1' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, HullDecoration) == 0x000BC8, "Member 'ABP_BRDMMinus2_C::HullDecoration' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, EngineComponent) == 0x000BD0, "Member 'ABP_BRDMMinus2_C::EngineComponent' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQVehicleResourceWeaponInventory) == 0x000BD8, "Member 'ABP_BRDMMinus2_C::SQVehicleResourceWeaponInventory' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQMapIcon) == 0x000BE0, "Member 'ABP_BRDMMinus2_C::SQMapIcon' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQVehicleBurning) == 0x000BE8, "Member 'ABP_BRDMMinus2_C::SQVehicleBurning' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQVehicleExitPoint1) == 0x000BF0, "Member 'ABP_BRDMMinus2_C::SQVehicleExitPoint1' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, SQVehicleExitPoint) == 0x000BF8, "Member 'ABP_BRDMMinus2_C::SQVehicleExitPoint' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, WheelDestroyedSound) == 0x000C00, "Member 'ABP_BRDMMinus2_C::WheelDestroyedSound' has a wrong offset!");
static_assert(offsetof(ABP_BRDMMinus2_C, WheelDestroyedEffect) == 0x000C08, "Member 'ABP_BRDMMinus2_C::WheelDestroyedEffect' has a wrong offset!");

}
