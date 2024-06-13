#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Minsk_Burn

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass minsk_Burn.minsk_Burn_C
// 0x0008 (0x03C0 - 0x03B8)
class AMinsk_Burn_C : public ASQDestroyedVehicle
{
public:
	class UBP_WreckSplashDamageComponent_C*       BP_WreckSplashDamageComponent;                     // 0x03B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"minsk_Burn_C">();
	}
	static class AMinsk_Burn_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AMinsk_Burn_C>();
	}
};
static_assert(alignof(AMinsk_Burn_C) == 0x000008, "Wrong alignment on AMinsk_Burn_C");
static_assert(sizeof(AMinsk_Burn_C) == 0x0003C0, "Wrong size on AMinsk_Burn_C");
static_assert(offsetof(AMinsk_Burn_C, BP_WreckSplashDamageComponent) == 0x0003B8, "Member 'AMinsk_Burn_C::BP_WreckSplashDamageComponent' has a wrong offset!");

}

