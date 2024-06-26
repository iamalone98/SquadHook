#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tracks_T62_Left

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Tracks_T62_Left.Tracks_T62_Left_C
// 0x00A0 (0x0328 - 0x0288)
class ATracks_T62_Left_C : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               BackDebris;                                        // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               FrontDebris;                                       // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               PanelFx;                                           // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce1;                                      // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh3;                                       // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh2;                                       // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh;                                        // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x02D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece10;                                           // 0x02D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece9;                                            // 0x02E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece8;                                            // 0x02E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece7;                                            // 0x02F0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x02F8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x0300(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece4;                                            // 0x0308(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x0310(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x0318(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x0320(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Tracks_T62_Left(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Tracks_T62_Left_C">();
	}
	static class ATracks_T62_Left_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATracks_T62_Left_C>();
	}
};
static_assert(alignof(ATracks_T62_Left_C) == 0x000008, "Wrong alignment on ATracks_T62_Left_C");
static_assert(sizeof(ATracks_T62_Left_C) == 0x000328, "Wrong size on ATracks_T62_Left_C");
static_assert(offsetof(ATracks_T62_Left_C, UberGraphFrame) == 0x000288, "Member 'ATracks_T62_Left_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, BackDebris) == 0x000290, "Member 'ATracks_T62_Left_C::BackDebris' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, FrontDebris) == 0x000298, "Member 'ATracks_T62_Left_C::FrontDebris' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, PanelFx) == 0x0002A0, "Member 'ATracks_T62_Left_C::PanelFx' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, RadialForce1) == 0x0002A8, "Member 'ATracks_T62_Left_C::RadialForce1' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, StaticMesh3) == 0x0002B0, "Member 'ATracks_T62_Left_C::StaticMesh3' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, StaticMesh2) == 0x0002B8, "Member 'ATracks_T62_Left_C::StaticMesh2' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, StaticMesh1) == 0x0002C0, "Member 'ATracks_T62_Left_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, StaticMesh) == 0x0002C8, "Member 'ATracks_T62_Left_C::StaticMesh' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, RadialForce) == 0x0002D0, "Member 'ATracks_T62_Left_C::RadialForce' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece10) == 0x0002D8, "Member 'ATracks_T62_Left_C::Piece10' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece9) == 0x0002E0, "Member 'ATracks_T62_Left_C::Piece9' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece8) == 0x0002E8, "Member 'ATracks_T62_Left_C::Piece8' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece7) == 0x0002F0, "Member 'ATracks_T62_Left_C::Piece7' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece6) == 0x0002F8, "Member 'ATracks_T62_Left_C::Piece6' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece5) == 0x000300, "Member 'ATracks_T62_Left_C::Piece5' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece4) == 0x000308, "Member 'ATracks_T62_Left_C::Piece4' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece3) == 0x000310, "Member 'ATracks_T62_Left_C::Piece3' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece2) == 0x000318, "Member 'ATracks_T62_Left_C::Piece2' has a wrong offset!");
static_assert(offsetof(ATracks_T62_Left_C, Piece1) == 0x000320, "Member 'ATracks_T62_Left_C::Piece1' has a wrong offset!");

}

