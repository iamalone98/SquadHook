#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Projectile_30mm_HE

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Projectile_30mm_HE.BP_Projectile_30mm_HE_C
// 0x0010 (0x0528 - 0x0518)
class ABP_Projectile_30mm_HE_C : public ASQMortarProjectile
{
public:
	class UStaticMesh*                            TracerMesh_0;                                      // 0x0518(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterial*                              TracerMaterial_0;                                  // 0x0520(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Projectile_30mm_HE_C">();
	}
	static class ABP_Projectile_30mm_HE_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Projectile_30mm_HE_C>();
	}
};
static_assert(alignof(ABP_Projectile_30mm_HE_C) == 0x000008, "Wrong alignment on ABP_Projectile_30mm_HE_C");
static_assert(sizeof(ABP_Projectile_30mm_HE_C) == 0x000528, "Wrong size on ABP_Projectile_30mm_HE_C");
static_assert(offsetof(ABP_Projectile_30mm_HE_C, TracerMesh_0) == 0x000518, "Member 'ABP_Projectile_30mm_HE_C::TracerMesh_0' has a wrong offset!");
static_assert(offsetof(ABP_Projectile_30mm_HE_C, TracerMaterial_0) == 0x000520, "Member 'ABP_Projectile_30mm_HE_C::TracerMaterial_0' has a wrong offset!");

}

