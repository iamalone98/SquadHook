#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tent_Destruction_Small

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Tent_Destruction_Small.Tent_Destruction_Small_C
// 0x0010 (0x0298 - 0x0288)
class ATent_Destruction_Small_C final : public ASQLastingEffect
{
public:
	class UParticleSystemComponent*               Fabric;                                            // 0x0288(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Explosion;                                         // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Tent_Destruction_Small_C">();
	}
	static class ATent_Destruction_Small_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATent_Destruction_Small_C>();
	}
};
static_assert(alignof(ATent_Destruction_Small_C) == 0x000008, "Wrong alignment on ATent_Destruction_Small_C");
static_assert(sizeof(ATent_Destruction_Small_C) == 0x000298, "Wrong size on ATent_Destruction_Small_C");
static_assert(offsetof(ATent_Destruction_Small_C, Fabric) == 0x000288, "Member 'ATent_Destruction_Small_C::Fabric' has a wrong offset!");
static_assert(offsetof(ATent_Destruction_Small_C, Explosion) == 0x000290, "Member 'ATent_Destruction_Small_C::Explosion' has a wrong offset!");

}

