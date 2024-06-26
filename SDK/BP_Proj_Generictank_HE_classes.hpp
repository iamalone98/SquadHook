#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Proj_Generictank_HE

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Proj_Generictank_HE.BP_Proj_Generictank_HE_C
// 0x0020 (0x0538 - 0x0518)
class ABP_Proj_Generictank_HE_C : public ASQMortarProjectile
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0518(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               ParticleSystem;                                    // 0x0520(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMesh*                            TracerMesh;                                        // 0x0528(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterial*                              TracerMaterial;                                    // 0x0530(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Proj_Generictank_HE(int32 EntryPoint);
	void OnImpact(class AActor* SelfActor, class AActor* OtherActor, const struct FVector& NormalImpulse, const struct FHitResult& Hit);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Proj_Generictank_HE_C">();
	}
	static class ABP_Proj_Generictank_HE_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Proj_Generictank_HE_C>();
	}
};
static_assert(alignof(ABP_Proj_Generictank_HE_C) == 0x000008, "Wrong alignment on ABP_Proj_Generictank_HE_C");
static_assert(sizeof(ABP_Proj_Generictank_HE_C) == 0x000538, "Wrong size on ABP_Proj_Generictank_HE_C");
static_assert(offsetof(ABP_Proj_Generictank_HE_C, UberGraphFrame) == 0x000518, "Member 'ABP_Proj_Generictank_HE_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_Proj_Generictank_HE_C, ParticleSystem) == 0x000520, "Member 'ABP_Proj_Generictank_HE_C::ParticleSystem' has a wrong offset!");
static_assert(offsetof(ABP_Proj_Generictank_HE_C, TracerMesh) == 0x000528, "Member 'ABP_Proj_Generictank_HE_C::TracerMesh' has a wrong offset!");
static_assert(offsetof(ABP_Proj_Generictank_HE_C, TracerMaterial) == 0x000530, "Member 'ABP_Proj_Generictank_HE_C::TracerMaterial' has a wrong offset!");

}

