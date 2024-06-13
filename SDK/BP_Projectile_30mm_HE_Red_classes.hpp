#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Projectile_30mm_HE_Red

#include "Basic.hpp"

#include "BP_Projectile_30mm_HE_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Projectile_30mm_HE_Red.BP_Projectile_30mm_HE_Red_C
// 0x0018 (0x0540 - 0x0528)
class ABP_Projectile_30mm_HE_Red_C : public ABP_Projectile_30mm_HE_C
{
public:
	class UParticleSystemComponent*               ParticleSystem;                                    // 0x0528(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMesh*                            TracerMesh_1;                                      // 0x0530(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterial*                              TracerMaterial_1;                                  // 0x0538(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Projectile_30mm_HE_Red_C">();
	}
	static class ABP_Projectile_30mm_HE_Red_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Projectile_30mm_HE_Red_C>();
	}
};
static_assert(alignof(ABP_Projectile_30mm_HE_Red_C) == 0x000008, "Wrong alignment on ABP_Projectile_30mm_HE_Red_C");
static_assert(sizeof(ABP_Projectile_30mm_HE_Red_C) == 0x000540, "Wrong size on ABP_Projectile_30mm_HE_Red_C");
static_assert(offsetof(ABP_Projectile_30mm_HE_Red_C, ParticleSystem) == 0x000528, "Member 'ABP_Projectile_30mm_HE_Red_C::ParticleSystem' has a wrong offset!");
static_assert(offsetof(ABP_Projectile_30mm_HE_Red_C, TracerMesh_1) == 0x000530, "Member 'ABP_Projectile_30mm_HE_Red_C::TracerMesh_1' has a wrong offset!");
static_assert(offsetof(ABP_Projectile_30mm_HE_Red_C, TracerMaterial_1) == 0x000538, "Member 'ABP_Projectile_30mm_HE_Red_C::TracerMaterial_1' has a wrong offset!");

}
