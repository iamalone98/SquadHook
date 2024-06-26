#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Techie_Wheel_Right

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Techie_Wheel_Right.Techie_Wheel_Right_C
// 0x0038 (0x02C0 - 0x0288)
class ATechie_Wheel_Right_C : public ASQLastingEffect
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0288(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               Steam3;                                            // 0x0290(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Steam2;                                            // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Steam;                                             // 0x02A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Wheel;                                             // 0x02A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh;                                        // 0x02B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class URadialForceComponent*                  RadialForce;                                       // 0x02B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_Techie_Wheel_Right(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Techie_Wheel_Right_C">();
	}
	static class ATechie_Wheel_Right_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATechie_Wheel_Right_C>();
	}
};
static_assert(alignof(ATechie_Wheel_Right_C) == 0x000008, "Wrong alignment on ATechie_Wheel_Right_C");
static_assert(sizeof(ATechie_Wheel_Right_C) == 0x0002C0, "Wrong size on ATechie_Wheel_Right_C");
static_assert(offsetof(ATechie_Wheel_Right_C, UberGraphFrame) == 0x000288, "Member 'ATechie_Wheel_Right_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, Steam3) == 0x000290, "Member 'ATechie_Wheel_Right_C::Steam3' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, Steam2) == 0x000298, "Member 'ATechie_Wheel_Right_C::Steam2' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, Steam) == 0x0002A0, "Member 'ATechie_Wheel_Right_C::Steam' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, Wheel) == 0x0002A8, "Member 'ATechie_Wheel_Right_C::Wheel' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, StaticMesh) == 0x0002B0, "Member 'ATechie_Wheel_Right_C::StaticMesh' has a wrong offset!");
static_assert(offsetof(ATechie_Wheel_Right_C, RadialForce) == 0x0002B8, "Member 'ATechie_Wheel_Right_C::RadialForce' has a wrong offset!");

}

