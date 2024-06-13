#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Sandbag_Half

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Sandbag_Half.Sandbag_Half_C
// 0x0040 (0x02C8 - 0x0288)
class ASandbag_Half_C : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class URadialForceComponent*                  RadialForce;                                       // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece4;                                            // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Sandbag_Half(int32 EntryPoint);
	void BndEvt__Piece6_K2Node_ComponentBoundEvent_16_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece5_K2Node_ComponentBoundEvent_13_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece4_K2Node_ComponentBoundEvent_10_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece3_K2Node_ComponentBoundEvent_7_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece2_K2Node_ComponentBoundEvent_4_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece1_K2Node_ComponentBoundEvent_0_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Sandbag_Half_C">();
	}
	static class ASandbag_Half_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ASandbag_Half_C>();
	}
};
static_assert(alignof(ASandbag_Half_C) == 0x000008, "Wrong alignment on ASandbag_Half_C");
static_assert(sizeof(ASandbag_Half_C) == 0x0002C8, "Wrong size on ASandbag_Half_C");
static_assert(offsetof(ASandbag_Half_C, UberGraphFrame) == 0x000288, "Member 'ASandbag_Half_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, RadialForce) == 0x000290, "Member 'ASandbag_Half_C::RadialForce' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece6) == 0x000298, "Member 'ASandbag_Half_C::Piece6' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece5) == 0x0002A0, "Member 'ASandbag_Half_C::Piece5' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece4) == 0x0002A8, "Member 'ASandbag_Half_C::Piece4' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece3) == 0x0002B0, "Member 'ASandbag_Half_C::Piece3' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece2) == 0x0002B8, "Member 'ASandbag_Half_C::Piece2' has a wrong offset!");
static_assert(offsetof(ASandbag_Half_C, Piece1) == 0x0002C0, "Member 'ASandbag_Half_C::Piece1' has a wrong offset!");

}
