#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Ural375_militia_destroyed

#include "Basic.hpp"

#include "BP_GenericDestroyedVehicleWreck_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass ural375_militia_destroyed.ural375_militia_destroyed_C
// 0x0008 (0x03C8 - 0x03C0)
class AUral375_militia_destroyed_C : public ABP_GenericDestroyedVehicleWreck_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMesh;                                       // 0x03C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"ural375_militia_destroyed_C">();
	}
	static class AUral375_militia_destroyed_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AUral375_militia_destroyed_C>();
	}
};
static_assert(alignof(AUral375_militia_destroyed_C) == 0x000008, "Wrong alignment on AUral375_militia_destroyed_C");
static_assert(sizeof(AUral375_militia_destroyed_C) == 0x0003C8, "Wrong size on AUral375_militia_destroyed_C");
static_assert(offsetof(AUral375_militia_destroyed_C, SQArmorMesh) == 0x0003C0, "Member 'AUral375_militia_destroyed_C::SQArmorMesh' has a wrong offset!");

}

