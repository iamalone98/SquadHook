#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Warrior_Destroy

#include "Basic.hpp"

#include "BP_GenericDestroyedVehicleWreck_Turreted_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Warrior_Destroy.Warrior_Destroy_C
// 0x0008 (0x03E0 - 0x03D8)
class AWarrior_Destroy_C : public ABP_GenericDestroyedVehicleWreck_Turreted_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x03D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Warrior_Destroy_C">();
	}
	static class AWarrior_Destroy_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AWarrior_Destroy_C>();
	}
};
static_assert(alignof(AWarrior_Destroy_C) == 0x000008, "Wrong alignment on AWarrior_Destroy_C");
static_assert(sizeof(AWarrior_Destroy_C) == 0x0003E0, "Wrong size on AWarrior_Destroy_C");
static_assert(offsetof(AWarrior_Destroy_C, SQArmorMesh) == 0x0003D8, "Member 'AWarrior_Destroy_C::SQArmorMesh' has a wrong offset!");

}
