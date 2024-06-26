#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Rubblepile_long

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass rubblepile_long.rubblepile_long_C
// 0x0020 (0x0248 - 0x0228)
class ARubblepile_long_C final : public AActor
{
public:
	class UStaticMeshComponent*                   Rubblepile6_0;                                     // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Rubblepile1_0;                                     // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Rubblepile2_0;                                     // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        Scene1;                                            // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"rubblepile_long_C">();
	}
	static class ARubblepile_long_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ARubblepile_long_C>();
	}
};
static_assert(alignof(ARubblepile_long_C) == 0x000008, "Wrong alignment on ARubblepile_long_C");
static_assert(sizeof(ARubblepile_long_C) == 0x000248, "Wrong size on ARubblepile_long_C");
static_assert(offsetof(ARubblepile_long_C, Rubblepile6_0) == 0x000228, "Member 'ARubblepile_long_C::Rubblepile6_0' has a wrong offset!");
static_assert(offsetof(ARubblepile_long_C, Rubblepile1_0) == 0x000230, "Member 'ARubblepile_long_C::Rubblepile1_0' has a wrong offset!");
static_assert(offsetof(ARubblepile_long_C, Rubblepile2_0) == 0x000238, "Member 'ARubblepile_long_C::Rubblepile2_0' has a wrong offset!");
static_assert(offsetof(ARubblepile_long_C, Scene1) == 0x000240, "Member 'ARubblepile_long_C::Scene1' has a wrong offset!");

}

