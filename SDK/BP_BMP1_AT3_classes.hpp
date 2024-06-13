#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BMP1_AT3

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_GenericVehicleGuidedMissileWeapon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BMP1_AT3.BP_BMP1_AT3_C
// 0x0030 (0x0CB0 - 0x0C80)
class ABP_BMP1_AT3_C final : public ABP_GenericVehicleGuidedMissileWeapon_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_BMP1_AT3_C;                      // 0x0C80(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	FMulticastInlineDelegateProperty_             AT3_OnFire;                                        // 0x0C88(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             AT3_OnReloaded;                                    // 0x0C98(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void AT3_OnFire__DelegateSignature();
	void AT3_OnReloaded__DelegateSignature();
	void ExecuteUbergraph_BP_BMP1_AT3(int32 EntryPoint);
	void BlueprintOnFire(const struct FVector& Origin);
	void BlueprintOnReloaded();
	void BlueprintOnReload();
	void PlayAnimations(class ASQSoldier* Soldier, class UAnimMontage* WeaponAnim, class UAnimMontage* TripodAnim, float* TripodAnimTime, float* WeaponAnimTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BMP1_AT3_C">();
	}
	static class ABP_BMP1_AT3_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BMP1_AT3_C>();
	}
};
static_assert(alignof(ABP_BMP1_AT3_C) == 0x000010, "Wrong alignment on ABP_BMP1_AT3_C");
static_assert(sizeof(ABP_BMP1_AT3_C) == 0x000CB0, "Wrong size on ABP_BMP1_AT3_C");
static_assert(offsetof(ABP_BMP1_AT3_C, UberGraphFrame_BP_BMP1_AT3_C) == 0x000C80, "Member 'ABP_BMP1_AT3_C::UberGraphFrame_BP_BMP1_AT3_C' has a wrong offset!");
static_assert(offsetof(ABP_BMP1_AT3_C, AT3_OnFire) == 0x000C88, "Member 'ABP_BMP1_AT3_C::AT3_OnFire' has a wrong offset!");
static_assert(offsetof(ABP_BMP1_AT3_C, AT3_OnReloaded) == 0x000C98, "Member 'ABP_BMP1_AT3_C::AT3_OnReloaded' has a wrong offset!");

}

