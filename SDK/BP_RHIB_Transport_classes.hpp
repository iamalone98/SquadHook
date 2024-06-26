#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RHIB_Transport

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RHIB_Transport.BP_RHIB_Transport_C
// 0x00B0 (0x0C10 - 0x0B60)
class ABP_RHIB_Transport_C final : public ASQWheeledVehicle
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0B60(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQWaterRudderComponent*                SQWaterRudder;                                     // 0x0B68(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   HorizontalFlag;                                    // 0x0B70(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint_Water3;                         // 0x0B78(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint5;                               // 0x0B80(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint4;                               // 0x0B88(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint3;                               // 0x0B90(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   RHIB_BoatInterior_MaskMesh;                        // 0x0B98(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQWaterThrusterComponent*              SQWaterThruster;                                   // 0x0BA0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       Compass;                                           // 0x0BA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBPComponent_RadialModel_C*             Vehicle_Radial;                                    // 0x0BB0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleEngine*                       EngineComponent;                                   // 0x0BB8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleResourceWeaponInventoryComponent* SQVehicleResourceWeaponInventory;                  // 0x0BC0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   CollisionMesh;                                     // 0x0BC8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQMapIconComponent*                    SQMapIcon;                                         // 0x0BD0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleBurningComponent*             SQVehicleBurning;                                  // 0x0BD8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint_Water2;                         // 0x0BE0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint2;                               // 0x0BE8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint_Water1;                         // 0x0BF0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               FlagMat;                                           // 0x0BF8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           FindFlagTimerHandle;                               // 0x0C00(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_RHIB_Transport(int32 EntryPoint);
	void AttemptFindFlagTexture();
	void ReceiveBeginPlay();
	void OnLoaded_53BB6EC540A8B1C8E9FF71B327568EB8(class UObject* Loaded);
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RHIB_Transport_C">();
	}
	static class ABP_RHIB_Transport_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RHIB_Transport_C>();
	}
};
static_assert(alignof(ABP_RHIB_Transport_C) == 0x000010, "Wrong alignment on ABP_RHIB_Transport_C");
static_assert(sizeof(ABP_RHIB_Transport_C) == 0x000C10, "Wrong size on ABP_RHIB_Transport_C");
static_assert(offsetof(ABP_RHIB_Transport_C, UberGraphFrame) == 0x000B60, "Member 'ABP_RHIB_Transport_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQWaterRudder) == 0x000B68, "Member 'ABP_RHIB_Transport_C::SQWaterRudder' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, HorizontalFlag) == 0x000B70, "Member 'ABP_RHIB_Transport_C::HorizontalFlag' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint_Water3) == 0x000B78, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint_Water3' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint5) == 0x000B80, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint5' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint4) == 0x000B88, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint4' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint3) == 0x000B90, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint3' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, RHIB_BoatInterior_MaskMesh) == 0x000B98, "Member 'ABP_RHIB_Transport_C::RHIB_BoatInterior_MaskMesh' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQWaterThruster) == 0x000BA0, "Member 'ABP_RHIB_Transport_C::SQWaterThruster' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, Compass) == 0x000BA8, "Member 'ABP_RHIB_Transport_C::Compass' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, Vehicle_Radial) == 0x000BB0, "Member 'ABP_RHIB_Transport_C::Vehicle_Radial' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, EngineComponent) == 0x000BB8, "Member 'ABP_RHIB_Transport_C::EngineComponent' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleResourceWeaponInventory) == 0x000BC0, "Member 'ABP_RHIB_Transport_C::SQVehicleResourceWeaponInventory' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, CollisionMesh) == 0x000BC8, "Member 'ABP_RHIB_Transport_C::CollisionMesh' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQMapIcon) == 0x000BD0, "Member 'ABP_RHIB_Transport_C::SQMapIcon' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleBurning) == 0x000BD8, "Member 'ABP_RHIB_Transport_C::SQVehicleBurning' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint_Water2) == 0x000BE0, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint_Water2' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint2) == 0x000BE8, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint2' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, SQVehicleExitPoint_Water1) == 0x000BF0, "Member 'ABP_RHIB_Transport_C::SQVehicleExitPoint_Water1' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, FlagMat) == 0x000BF8, "Member 'ABP_RHIB_Transport_C::FlagMat' has a wrong offset!");
static_assert(offsetof(ABP_RHIB_Transport_C, FindFlagTimerHandle) == 0x000C00, "Member 'ABP_RHIB_Transport_C::FindFlagTimerHandle' has a wrong offset!");

}

