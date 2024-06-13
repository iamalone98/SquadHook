#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedM2_Tripod

#include "Basic.hpp"

#include "BP_GenericDeployableTripodVehicle_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmplacedM2_Tripod.BP_EmplacedM2_Tripod_C
// 0x0010 (0x09E0 - 0x09D0)
class ABP_EmplacedM2_Tripod_C : public ABP_GenericDeployableTripodVehicle_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMeshTripod;                                 // 0x09D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x09D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	class USceneComponent* GetSoldierAttachComponent() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmplacedM2_Tripod_C">();
	}
	static class ABP_EmplacedM2_Tripod_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_EmplacedM2_Tripod_C>();
	}
};
static_assert(alignof(ABP_EmplacedM2_Tripod_C) == 0x000010, "Wrong alignment on ABP_EmplacedM2_Tripod_C");
static_assert(sizeof(ABP_EmplacedM2_Tripod_C) == 0x0009E0, "Wrong size on ABP_EmplacedM2_Tripod_C");
static_assert(offsetof(ABP_EmplacedM2_Tripod_C, SQArmorMeshTripod) == 0x0009D0, "Member 'ABP_EmplacedM2_Tripod_C::SQArmorMeshTripod' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedM2_Tripod_C, SQArmorMesh) == 0x0009D8, "Member 'ABP_EmplacedM2_Tripod_C::SQArmorMesh' has a wrong offset!");

}
