#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedM2_Weapon

#include "Basic.hpp"

#include "BP_GenericDeployableWeapon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmplacedM2_Weapon.BP_EmplacedM2_Weapon_C
// 0x0000 (0x0D30 - 0x0D30)
class ABP_EmplacedM2_Weapon_C : public ABP_GenericDeployableWeapon_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmplacedM2_Weapon_C">();
	}
	static class ABP_EmplacedM2_Weapon_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_EmplacedM2_Weapon_C>();
	}
};
static_assert(alignof(ABP_EmplacedM2_Weapon_C) == 0x000010, "Wrong alignment on ABP_EmplacedM2_Weapon_C");
static_assert(sizeof(ABP_EmplacedM2_Weapon_C) == 0x000D30, "Wrong size on ABP_EmplacedM2_Weapon_C");

}

