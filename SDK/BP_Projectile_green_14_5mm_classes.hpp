#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Projectile_green_14_5mm

#include "Basic.hpp"

#include "BP_Projectile_14_5mm_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Projectile_green_14_5mm.BP_Projectile_green_14_5mm_C
// 0x0008 (0x0490 - 0x0488)
class ABP_Projectile_green_14_5mm_C final : public ABP_Projectile_14_5mm_C
{
public:
	class UParticleSystemComponent*               ParticleSystem;                                    // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Projectile_green_14_5mm_C">();
	}
	static class ABP_Projectile_green_14_5mm_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Projectile_green_14_5mm_C>();
	}
};
static_assert(alignof(ABP_Projectile_green_14_5mm_C) == 0x000008, "Wrong alignment on ABP_Projectile_green_14_5mm_C");
static_assert(sizeof(ABP_Projectile_green_14_5mm_C) == 0x000490, "Wrong size on ABP_Projectile_green_14_5mm_C");
static_assert(offsetof(ABP_Projectile_green_14_5mm_C, ParticleSystem) == 0x000488, "Member 'ABP_Projectile_green_14_5mm_C::ParticleSystem' has a wrong offset!");

}

