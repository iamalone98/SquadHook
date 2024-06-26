#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Trashpile_barrelramp

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass trashpile_barrelramp.trashpile_barrelramp_C
// 0x0028 (0x0250 - 0x0228)
class ATrashpile_barrelramp_C final : public AActor
{
public:
	class UStaticMeshComponent*                   StaticMeshComponent03;                             // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMeshComponent02;                             // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMeshComponent01;                             // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMeshComponent0;                              // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        SharedRoot;                                        // 0x0248(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"trashpile_barrelramp_C">();
	}
	static class ATrashpile_barrelramp_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATrashpile_barrelramp_C>();
	}
};
static_assert(alignof(ATrashpile_barrelramp_C) == 0x000008, "Wrong alignment on ATrashpile_barrelramp_C");
static_assert(sizeof(ATrashpile_barrelramp_C) == 0x000250, "Wrong size on ATrashpile_barrelramp_C");
static_assert(offsetof(ATrashpile_barrelramp_C, StaticMeshComponent03) == 0x000228, "Member 'ATrashpile_barrelramp_C::StaticMeshComponent03' has a wrong offset!");
static_assert(offsetof(ATrashpile_barrelramp_C, StaticMeshComponent02) == 0x000230, "Member 'ATrashpile_barrelramp_C::StaticMeshComponent02' has a wrong offset!");
static_assert(offsetof(ATrashpile_barrelramp_C, StaticMeshComponent01) == 0x000238, "Member 'ATrashpile_barrelramp_C::StaticMeshComponent01' has a wrong offset!");
static_assert(offsetof(ATrashpile_barrelramp_C, StaticMeshComponent0) == 0x000240, "Member 'ATrashpile_barrelramp_C::StaticMeshComponent0' has a wrong offset!");
static_assert(offsetof(ATrashpile_barrelramp_C, SharedRoot) == 0x000248, "Member 'ATrashpile_barrelramp_C::SharedRoot' has a wrong offset!");

}

