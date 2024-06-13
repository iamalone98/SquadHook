#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ZU23Vehicle_Base

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_GenericVehicleOpenTurret_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_ZU23Vehicle_Base.BP_ZU23Vehicle_Base_C
// 0x0020 (0x0490 - 0x0470)
class ABP_ZU23Vehicle_Base_C : public ABP_GenericVehicleOpenTurret_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_ZU23Vehicle_Base_C;              // 0x0470(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class ABP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_C* WeaponRef;                                         // 0x0480(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_ZU23Vehicle_Base(int32 EntryPoint);
	void ReceiveTick(float DeltaSeconds);

	class USceneComponent* GetADSCameraLocationComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_ZU23Vehicle_Base_C">();
	}
	static class ABP_ZU23Vehicle_Base_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_ZU23Vehicle_Base_C>();
	}
};
static_assert(alignof(ABP_ZU23Vehicle_Base_C) == 0x000010, "Wrong alignment on ABP_ZU23Vehicle_Base_C");
static_assert(sizeof(ABP_ZU23Vehicle_Base_C) == 0x000490, "Wrong size on ABP_ZU23Vehicle_Base_C");
static_assert(offsetof(ABP_ZU23Vehicle_Base_C, UberGraphFrame_BP_ZU23Vehicle_Base_C) == 0x000470, "Member 'ABP_ZU23Vehicle_Base_C::UberGraphFrame_BP_ZU23Vehicle_Base_C' has a wrong offset!");
static_assert(offsetof(ABP_ZU23Vehicle_Base_C, SQArmorMesh) == 0x000478, "Member 'ABP_ZU23Vehicle_Base_C::SQArmorMesh' has a wrong offset!");
static_assert(offsetof(ABP_ZU23Vehicle_Base_C, WeaponRef) == 0x000480, "Member 'ABP_ZU23Vehicle_Base_C::WeaponRef' has a wrong offset!");

}

