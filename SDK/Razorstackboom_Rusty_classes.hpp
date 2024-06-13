#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Razorstackboom_Rusty

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Razorstackboom_Rusty.Razorstackboom_Rusty_C
// 0x0058 (0x02E0 - 0x0288)
class ARazorstackboom_Rusty_C final : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               Razorstop;                                         // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece8;                                            // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece7;                                            // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece6;                                            // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece5;                                            // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece4;                                            // 0x02C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece3;                                            // 0x02C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece2;                                            // 0x02D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Piece1;                                            // 0x02D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Razorstackboom_Rusty(int32 EntryPoint);
	void BndEvt__Piece7_K2Node_ComponentBoundEvent_30_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece5_K2Node_ComponentBoundEvent_6_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece6_K2Node_ComponentBoundEvent_16_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece2_K2Node_ComponentBoundEvent_8_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece1_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void BndEvt__Piece4_K2Node_ComponentBoundEvent_20_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Razorstackboom_Rusty_C">();
	}
	static class ARazorstackboom_Rusty_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ARazorstackboom_Rusty_C>();
	}
};
static_assert(alignof(ARazorstackboom_Rusty_C) == 0x000008, "Wrong alignment on ARazorstackboom_Rusty_C");
static_assert(sizeof(ARazorstackboom_Rusty_C) == 0x0002E0, "Wrong size on ARazorstackboom_Rusty_C");
static_assert(offsetof(ARazorstackboom_Rusty_C, UberGraphFrame) == 0x000288, "Member 'ARazorstackboom_Rusty_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Razorstop) == 0x000290, "Member 'ARazorstackboom_Rusty_C::Razorstop' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece8) == 0x000298, "Member 'ARazorstackboom_Rusty_C::Piece8' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece7) == 0x0002A0, "Member 'ARazorstackboom_Rusty_C::Piece7' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece6) == 0x0002A8, "Member 'ARazorstackboom_Rusty_C::Piece6' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece5) == 0x0002B0, "Member 'ARazorstackboom_Rusty_C::Piece5' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, RadialForce) == 0x0002B8, "Member 'ARazorstackboom_Rusty_C::RadialForce' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece4) == 0x0002C0, "Member 'ARazorstackboom_Rusty_C::Piece4' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece3) == 0x0002C8, "Member 'ARazorstackboom_Rusty_C::Piece3' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece2) == 0x0002D0, "Member 'ARazorstackboom_Rusty_C::Piece2' has a wrong offset!");
static_assert(offsetof(ARazorstackboom_Rusty_C, Piece1) == 0x0002D8, "Member 'ARazorstackboom_Rusty_C::Piece1' has a wrong offset!");

}

