#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Dest_RepairUSHalf

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Dest_RepairUSHalf.Dest_RepairUSHalf_C
// 0x00D0 (0x0358 - 0x0288)
class ADest_RepairUSHalf_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   StaticMesh5;                                       // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh4;                                       // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh3;                                       // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh2;                                       // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh;                                        // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystem1;                                   // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Sandbag_exp2;                                      // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Sandbag_exp;                                       // 0x02D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce1;                                      // 0x02D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece20;                                           // 0x02E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece19;                                           // 0x02E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece18;                                           // 0x02F0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece17;                                           // 0x02F8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece16;                                           // 0x0300(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece15;                                           // 0x0308(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece14;                                           // 0x0310(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece13;                                           // 0x0318(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece12;                                           // 0x0320(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece11;                                           // 0x0328(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece8;                                            // 0x0330(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece7;                                            // 0x0338(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x0340(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x0348(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x0350(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Dest_RepairUSHalf(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Dest_RepairUSHalf_C">();
	}
	static class ADest_RepairUSHalf_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ADest_RepairUSHalf_C>();
	}
};
static_assert(alignof(ADest_RepairUSHalf_C) == 0x000008, "Wrong alignment on ADest_RepairUSHalf_C");
static_assert(sizeof(ADest_RepairUSHalf_C) == 0x000358, "Wrong size on ADest_RepairUSHalf_C");
static_assert(offsetof(ADest_RepairUSHalf_C, UberGraphFrame) == 0x000288, "Member 'ADest_RepairUSHalf_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh5) == 0x000290, "Member 'ADest_RepairUSHalf_C::StaticMesh5' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh4) == 0x000298, "Member 'ADest_RepairUSHalf_C::StaticMesh4' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh3) == 0x0002A0, "Member 'ADest_RepairUSHalf_C::StaticMesh3' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh2) == 0x0002A8, "Member 'ADest_RepairUSHalf_C::StaticMesh2' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh1) == 0x0002B0, "Member 'ADest_RepairUSHalf_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, StaticMesh) == 0x0002B8, "Member 'ADest_RepairUSHalf_C::StaticMesh' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, ParticleSystem1) == 0x0002C0, "Member 'ADest_RepairUSHalf_C::ParticleSystem1' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Sandbag_exp2) == 0x0002C8, "Member 'ADest_RepairUSHalf_C::Sandbag_exp2' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Sandbag_exp) == 0x0002D0, "Member 'ADest_RepairUSHalf_C::Sandbag_exp' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, RadialForce1) == 0x0002D8, "Member 'ADest_RepairUSHalf_C::RadialForce1' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece20) == 0x0002E0, "Member 'ADest_RepairUSHalf_C::Piece20' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece19) == 0x0002E8, "Member 'ADest_RepairUSHalf_C::Piece19' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece18) == 0x0002F0, "Member 'ADest_RepairUSHalf_C::Piece18' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece17) == 0x0002F8, "Member 'ADest_RepairUSHalf_C::Piece17' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece16) == 0x000300, "Member 'ADest_RepairUSHalf_C::Piece16' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece15) == 0x000308, "Member 'ADest_RepairUSHalf_C::Piece15' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece14) == 0x000310, "Member 'ADest_RepairUSHalf_C::Piece14' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece13) == 0x000318, "Member 'ADest_RepairUSHalf_C::Piece13' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece12) == 0x000320, "Member 'ADest_RepairUSHalf_C::Piece12' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece11) == 0x000328, "Member 'ADest_RepairUSHalf_C::Piece11' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece8) == 0x000330, "Member 'ADest_RepairUSHalf_C::Piece8' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece7) == 0x000338, "Member 'ADest_RepairUSHalf_C::Piece7' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece6) == 0x000340, "Member 'ADest_RepairUSHalf_C::Piece6' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, Piece5) == 0x000348, "Member 'ADest_RepairUSHalf_C::Piece5' has a wrong offset!");
static_assert(offsetof(ADest_RepairUSHalf_C, RadialForce) == 0x000350, "Member 'ADest_RepairUSHalf_C::RadialForce' has a wrong offset!");

}
