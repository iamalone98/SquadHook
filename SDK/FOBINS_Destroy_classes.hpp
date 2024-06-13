#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FOBINS_Destroy

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass FOBINS_Destroy.FOBINS_Destroy_C
// 0x0028 (0x02B0 - 0x0288)
class AFOBINS_Destroy_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class URadialForceComponent*                  RadialForce;                                       // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_FOBINS_Destroy(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"FOBINS_Destroy_C">();
	}
	static class AFOBINS_Destroy_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AFOBINS_Destroy_C>();
	}
};
static_assert(alignof(AFOBINS_Destroy_C) == 0x000008, "Wrong alignment on AFOBINS_Destroy_C");
static_assert(sizeof(AFOBINS_Destroy_C) == 0x0002B0, "Wrong size on AFOBINS_Destroy_C");
static_assert(offsetof(AFOBINS_Destroy_C, UberGraphFrame) == 0x000288, "Member 'AFOBINS_Destroy_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(AFOBINS_Destroy_C, RadialForce) == 0x000290, "Member 'AFOBINS_Destroy_C::RadialForce' has a wrong offset!");
static_assert(offsetof(AFOBINS_Destroy_C, Piece3) == 0x000298, "Member 'AFOBINS_Destroy_C::Piece3' has a wrong offset!");
static_assert(offsetof(AFOBINS_Destroy_C, Piece2) == 0x0002A0, "Member 'AFOBINS_Destroy_C::Piece2' has a wrong offset!");
static_assert(offsetof(AFOBINS_Destroy_C, Piece1) == 0x0002A8, "Member 'AFOBINS_Destroy_C::Piece1' has a wrong offset!");

}

