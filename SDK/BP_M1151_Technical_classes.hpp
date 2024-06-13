#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_M1151_Technical

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_M1151_Technical.BP_M1151_Technical_C
// 0x00A0 (0x0C00 - 0x0B60)
class ABP_M1151_Technical_C final : public ASQWheeledVehicle
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0B60(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQVehicleExitPointComponent*           SQVehicleExitPointWater;                           // 0x0B68(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMeshTechnicalArmor;                         // 0x0B70(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0B78(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Supplies1;                                         // 0x0B80(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Supplies;                                          // 0x0B88(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBPComponent_RadialModel_C*             Vehicle_Radial;                                    // 0x0B90(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleEngine*                       Non_Pen_Wall;                                      // 0x0B98(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleEngine*                       EngineComponent;                                   // 0x0BA0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_R1;                                          // 0x0BA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_R2;                                          // 0x0BB0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_L2;                                          // 0x0BB8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleWheel*                        Wheel_L1;                                          // 0x0BC0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleResourceWeaponInventoryComponent* SQVehicleResourceWeaponInventory;                  // 0x0BC8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQMapIconComponent*                    SQMapIcon;                                         // 0x0BD0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleBurningComponent*             SQVehicleBurning;                                  // 0x0BD8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint2;                               // 0x0BE0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint;                                // 0x0BE8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	struct FVector                                L_Scale;                                           // 0x0BF0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_M1151_Technical(int32 EntryPoint);
	void DrivetrainComponentRepaired(class USQDriveTrainComponent* DriveTrainComponent);
	void DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent);
	void UpdateDamageWheelVisual(class FName Bone, bool Destroyed, class USQVehicleWheel* Wheel, bool Do_Effects);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_M1151_Technical_C">();
	}
	static class ABP_M1151_Technical_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_M1151_Technical_C>();
	}
};
static_assert(alignof(ABP_M1151_Technical_C) == 0x000010, "Wrong alignment on ABP_M1151_Technical_C");
static_assert(sizeof(ABP_M1151_Technical_C) == 0x000C00, "Wrong size on ABP_M1151_Technical_C");
static_assert(offsetof(ABP_M1151_Technical_C, UberGraphFrame) == 0x000B60, "Member 'ABP_M1151_Technical_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQVehicleExitPointWater) == 0x000B68, "Member 'ABP_M1151_Technical_C::SQVehicleExitPointWater' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQArmorMeshTechnicalArmor) == 0x000B70, "Member 'ABP_M1151_Technical_C::SQArmorMeshTechnicalArmor' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQArmorMesh) == 0x000B78, "Member 'ABP_M1151_Technical_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Supplies1) == 0x000B80, "Member 'ABP_M1151_Technical_C::Supplies1' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Supplies) == 0x000B88, "Member 'ABP_M1151_Technical_C::Supplies' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Vehicle_Radial) == 0x000B90, "Member 'ABP_M1151_Technical_C::Vehicle_Radial' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Non_Pen_Wall) == 0x000B98, "Member 'ABP_M1151_Technical_C::Non_Pen_Wall' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, EngineComponent) == 0x000BA0, "Member 'ABP_M1151_Technical_C::EngineComponent' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Wheel_R1) == 0x000BA8, "Member 'ABP_M1151_Technical_C::Wheel_R1' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Wheel_R2) == 0x000BB0, "Member 'ABP_M1151_Technical_C::Wheel_R2' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Wheel_L2) == 0x000BB8, "Member 'ABP_M1151_Technical_C::Wheel_L2' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, Wheel_L1) == 0x000BC0, "Member 'ABP_M1151_Technical_C::Wheel_L1' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQVehicleResourceWeaponInventory) == 0x000BC8, "Member 'ABP_M1151_Technical_C::SQVehicleResourceWeaponInventory' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQMapIcon) == 0x000BD0, "Member 'ABP_M1151_Technical_C::SQMapIcon' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQVehicleBurning) == 0x000BD8, "Member 'ABP_M1151_Technical_C::SQVehicleBurning' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQVehicleExitPoint2) == 0x000BE0, "Member 'ABP_M1151_Technical_C::SQVehicleExitPoint2' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, SQVehicleExitPoint) == 0x000BE8, "Member 'ABP_M1151_Technical_C::SQVehicleExitPoint' has a wrong offset!");
static_assert(offsetof(ABP_M1151_Technical_C, L_Scale) == 0x000BF0, "Member 'ABP_M1151_Technical_C::L_Scale' has a wrong offset!");

}

