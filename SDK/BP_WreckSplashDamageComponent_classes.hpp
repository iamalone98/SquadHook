#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_WreckSplashDamageComponent

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_WreckSplashDamageComponent.BP_WreckSplashDamageComponent_C
// 0x0050 (0x0250 - 0x0200)
class UBP_WreckSplashDamageComponent_C final : public USceneComponent
{
public:
	uint8                                         Pad_2E0B[0x8];                                     // 0x01F8(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0200(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UClass*                                 DamageType;                                        // 0x0208(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         BaseDamage;                                        // 0x0210(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MinDamage;                                         // 0x0214(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         KillZone_Radius;                                   // 0x0218(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         InnerRadius;                                       // 0x021C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OuterRadius;                                       // 0x0220(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         DamageFalloff;                                     // 0x0224(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             OriginalVehicle;                                   // 0x0228(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            LastDamageInstigator;                              // 0x0230(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 Owner;                                             // 0x0238(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bAutoCenterOnVehicleMesh;                          // 0x0240(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bEnabled;                                          // 0x0241(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_BP_WreckSplashDamageComponent(int32 EntryPoint);
	void ReceiveBeginPlay();
	void SplashDamage();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_WreckSplashDamageComponent_C">();
	}
	static class UBP_WreckSplashDamageComponent_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_WreckSplashDamageComponent_C>();
	}
};
static_assert(alignof(UBP_WreckSplashDamageComponent_C) == 0x000010, "Wrong alignment on UBP_WreckSplashDamageComponent_C");
static_assert(sizeof(UBP_WreckSplashDamageComponent_C) == 0x000250, "Wrong size on UBP_WreckSplashDamageComponent_C");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, UberGraphFrame) == 0x000200, "Member 'UBP_WreckSplashDamageComponent_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, DamageType) == 0x000208, "Member 'UBP_WreckSplashDamageComponent_C::DamageType' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, BaseDamage) == 0x000210, "Member 'UBP_WreckSplashDamageComponent_C::BaseDamage' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, MinDamage) == 0x000214, "Member 'UBP_WreckSplashDamageComponent_C::MinDamage' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, KillZone_Radius) == 0x000218, "Member 'UBP_WreckSplashDamageComponent_C::KillZone_Radius' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, InnerRadius) == 0x00021C, "Member 'UBP_WreckSplashDamageComponent_C::InnerRadius' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, OuterRadius) == 0x000220, "Member 'UBP_WreckSplashDamageComponent_C::OuterRadius' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, DamageFalloff) == 0x000224, "Member 'UBP_WreckSplashDamageComponent_C::DamageFalloff' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, OriginalVehicle) == 0x000228, "Member 'UBP_WreckSplashDamageComponent_C::OriginalVehicle' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, LastDamageInstigator) == 0x000230, "Member 'UBP_WreckSplashDamageComponent_C::LastDamageInstigator' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, Owner) == 0x000238, "Member 'UBP_WreckSplashDamageComponent_C::Owner' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, bAutoCenterOnVehicleMesh) == 0x000240, "Member 'UBP_WreckSplashDamageComponent_C::bAutoCenterOnVehicleMesh' has a wrong offset!");
static_assert(offsetof(UBP_WreckSplashDamageComponent_C, bEnabled) == 0x000241, "Member 'UBP_WreckSplashDamageComponent_C::bEnabled' has a wrong offset!");

}
