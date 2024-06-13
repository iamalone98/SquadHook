#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Cushions2

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass cushions2.cushions2_C
// 0x0038 (0x0260 - 0x0228)
class ACushions2_C final : public AActor
{
public:
	class UStaticMeshComponent*                   Cushion1;                                          // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Cushion2_alt;                                      // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Cushion2;                                          // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Cushion3;                                          // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Mattress_green;                                    // 0x0248(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Mattress_alt;                                      // 0x0250(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0258(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"cushions2_C">();
	}
	static class ACushions2_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ACushions2_C>();
	}
};
static_assert(alignof(ACushions2_C) == 0x000008, "Wrong alignment on ACushions2_C");
static_assert(sizeof(ACushions2_C) == 0x000260, "Wrong size on ACushions2_C");
static_assert(offsetof(ACushions2_C, Cushion1) == 0x000228, "Member 'ACushions2_C::Cushion1' has a wrong offset!");
static_assert(offsetof(ACushions2_C, Cushion2_alt) == 0x000230, "Member 'ACushions2_C::Cushion2_alt' has a wrong offset!");
static_assert(offsetof(ACushions2_C, Cushion2) == 0x000238, "Member 'ACushions2_C::Cushion2' has a wrong offset!");
static_assert(offsetof(ACushions2_C, Cushion3) == 0x000240, "Member 'ACushions2_C::Cushion3' has a wrong offset!");
static_assert(offsetof(ACushions2_C, Mattress_green) == 0x000248, "Member 'ACushions2_C::Mattress_green' has a wrong offset!");
static_assert(offsetof(ACushions2_C, Mattress_alt) == 0x000250, "Member 'ACushions2_C::Mattress_alt' has a wrong offset!");
static_assert(offsetof(ACushions2_C, DefaultSceneRoot) == 0x000258, "Member 'ACushions2_C::DefaultSceneRoot' has a wrong offset!");

}

