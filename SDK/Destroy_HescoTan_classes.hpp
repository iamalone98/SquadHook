#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Destroy_HescoTan

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Destroy_HescoTan.Destroy_HescoTan_C
// 0x0048 (0x02D0 - 0x0288)
class ADestroy_HescoTan_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   Piece7;                                            // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece4;                                            // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Destroy_HescoTan(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Destroy_HescoTan_C">();
	}
	static class ADestroy_HescoTan_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ADestroy_HescoTan_C>();
	}
};
static_assert(alignof(ADestroy_HescoTan_C) == 0x000008, "Wrong alignment on ADestroy_HescoTan_C");
static_assert(sizeof(ADestroy_HescoTan_C) == 0x0002D0, "Wrong size on ADestroy_HescoTan_C");
static_assert(offsetof(ADestroy_HescoTan_C, UberGraphFrame) == 0x000288, "Member 'ADestroy_HescoTan_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece7) == 0x000290, "Member 'ADestroy_HescoTan_C::Piece7' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, RadialForce) == 0x000298, "Member 'ADestroy_HescoTan_C::RadialForce' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece6) == 0x0002A0, "Member 'ADestroy_HescoTan_C::Piece6' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece5) == 0x0002A8, "Member 'ADestroy_HescoTan_C::Piece5' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece4) == 0x0002B0, "Member 'ADestroy_HescoTan_C::Piece4' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece3) == 0x0002B8, "Member 'ADestroy_HescoTan_C::Piece3' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece2) == 0x0002C0, "Member 'ADestroy_HescoTan_C::Piece2' has a wrong offset!");
static_assert(offsetof(ADestroy_HescoTan_C, Piece1) == 0x0002C8, "Member 'ADestroy_HescoTan_C::Piece1' has a wrong offset!");

}

