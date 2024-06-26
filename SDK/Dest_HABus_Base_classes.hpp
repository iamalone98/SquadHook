#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Dest_HABus_Base

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Dest_HABus_Base.Dest_HABus_Base_C
// 0x00F8 (0x0380 - 0x0288)
class ADest_HABus_Base_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               DestroyVFX;                                        // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   WoodBeam4;                                         // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   WoodBeam3;                                         // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   WoodBeam2;                                         // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   WoodBeam;                                          // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystem4;                                   // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystem3;                                   // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystem2;                                   // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystem1;                                   // 0x02D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece20;                                           // 0x02D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece19;                                           // 0x02E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece18;                                           // 0x02E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece17;                                           // 0x02F0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece16;                                           // 0x02F8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece15;                                           // 0x0300(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece14;                                           // 0x0308(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece13;                                           // 0x0310(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece12;                                           // 0x0318(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece11;                                           // 0x0320(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece10;                                           // 0x0328(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece9;                                            // 0x0330(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece8;                                            // 0x0338(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece7;                                            // 0x0340(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x0348(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x0350(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece4;                                            // 0x0358(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x0360(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x0368(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x0370(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x0378(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Dest_HABus_Base(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Dest_HABus_Base_C">();
	}
	static class ADest_HABus_Base_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ADest_HABus_Base_C>();
	}
};
static_assert(alignof(ADest_HABus_Base_C) == 0x000008, "Wrong alignment on ADest_HABus_Base_C");
static_assert(sizeof(ADest_HABus_Base_C) == 0x000380, "Wrong size on ADest_HABus_Base_C");
static_assert(offsetof(ADest_HABus_Base_C, UberGraphFrame) == 0x000288, "Member 'ADest_HABus_Base_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, DestroyVFX) == 0x000290, "Member 'ADest_HABus_Base_C::DestroyVFX' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, WoodBeam4) == 0x000298, "Member 'ADest_HABus_Base_C::WoodBeam4' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, WoodBeam3) == 0x0002A0, "Member 'ADest_HABus_Base_C::WoodBeam3' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, WoodBeam2) == 0x0002A8, "Member 'ADest_HABus_Base_C::WoodBeam2' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, WoodBeam) == 0x0002B0, "Member 'ADest_HABus_Base_C::WoodBeam' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, ParticleSystem4) == 0x0002B8, "Member 'ADest_HABus_Base_C::ParticleSystem4' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, ParticleSystem3) == 0x0002C0, "Member 'ADest_HABus_Base_C::ParticleSystem3' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, ParticleSystem2) == 0x0002C8, "Member 'ADest_HABus_Base_C::ParticleSystem2' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, ParticleSystem1) == 0x0002D0, "Member 'ADest_HABus_Base_C::ParticleSystem1' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece20) == 0x0002D8, "Member 'ADest_HABus_Base_C::Piece20' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece19) == 0x0002E0, "Member 'ADest_HABus_Base_C::Piece19' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece18) == 0x0002E8, "Member 'ADest_HABus_Base_C::Piece18' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece17) == 0x0002F0, "Member 'ADest_HABus_Base_C::Piece17' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece16) == 0x0002F8, "Member 'ADest_HABus_Base_C::Piece16' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece15) == 0x000300, "Member 'ADest_HABus_Base_C::Piece15' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece14) == 0x000308, "Member 'ADest_HABus_Base_C::Piece14' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece13) == 0x000310, "Member 'ADest_HABus_Base_C::Piece13' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece12) == 0x000318, "Member 'ADest_HABus_Base_C::Piece12' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece11) == 0x000320, "Member 'ADest_HABus_Base_C::Piece11' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece10) == 0x000328, "Member 'ADest_HABus_Base_C::Piece10' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece9) == 0x000330, "Member 'ADest_HABus_Base_C::Piece9' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece8) == 0x000338, "Member 'ADest_HABus_Base_C::Piece8' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece7) == 0x000340, "Member 'ADest_HABus_Base_C::Piece7' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece6) == 0x000348, "Member 'ADest_HABus_Base_C::Piece6' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece5) == 0x000350, "Member 'ADest_HABus_Base_C::Piece5' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece4) == 0x000358, "Member 'ADest_HABus_Base_C::Piece4' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, RadialForce) == 0x000360, "Member 'ADest_HABus_Base_C::RadialForce' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece3) == 0x000368, "Member 'ADest_HABus_Base_C::Piece3' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece2) == 0x000370, "Member 'ADest_HABus_Base_C::Piece2' has a wrong offset!");
static_assert(offsetof(ADest_HABus_Base_C, Piece1) == 0x000378, "Member 'ADest_HABus_Base_C::Piece1' has a wrong offset!");

}

