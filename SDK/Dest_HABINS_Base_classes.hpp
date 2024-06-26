#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Dest_HABINS_Base

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Dest_HABINS_Base.Dest_HABINS_Base_C
// 0x0068 (0x02F0 - 0x0288)
class ADest_HABINS_Base_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   StaticMesh8;                                       // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh7;                                       // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh6;                                       // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh5;                                       // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh4;                                       // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh3;                                       // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh2;                                       // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh;                                        // 0x02D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Explosion;                                         // 0x02D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   WoodBeam;                                          // 0x02E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x02E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Dest_HABINS_Base(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Dest_HABINS_Base_C">();
	}
	static class ADest_HABINS_Base_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ADest_HABINS_Base_C>();
	}
};
static_assert(alignof(ADest_HABINS_Base_C) == 0x000008, "Wrong alignment on ADest_HABINS_Base_C");
static_assert(sizeof(ADest_HABINS_Base_C) == 0x0002F0, "Wrong size on ADest_HABINS_Base_C");
static_assert(offsetof(ADest_HABINS_Base_C, UberGraphFrame) == 0x000288, "Member 'ADest_HABINS_Base_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh8) == 0x000290, "Member 'ADest_HABINS_Base_C::StaticMesh8' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh7) == 0x000298, "Member 'ADest_HABINS_Base_C::StaticMesh7' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh6) == 0x0002A0, "Member 'ADest_HABINS_Base_C::StaticMesh6' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh5) == 0x0002A8, "Member 'ADest_HABINS_Base_C::StaticMesh5' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh4) == 0x0002B0, "Member 'ADest_HABINS_Base_C::StaticMesh4' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh3) == 0x0002B8, "Member 'ADest_HABINS_Base_C::StaticMesh3' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh2) == 0x0002C0, "Member 'ADest_HABINS_Base_C::StaticMesh2' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh1) == 0x0002C8, "Member 'ADest_HABINS_Base_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, StaticMesh) == 0x0002D0, "Member 'ADest_HABINS_Base_C::StaticMesh' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, Explosion) == 0x0002D8, "Member 'ADest_HABINS_Base_C::Explosion' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, WoodBeam) == 0x0002E0, "Member 'ADest_HABINS_Base_C::WoodBeam' has a wrong offset!");
static_assert(offsetof(ADest_HABINS_Base_C, RadialForce) == 0x0002E8, "Member 'ADest_HABINS_Base_C::RadialForce' has a wrong offset!");

}

