#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Projectile_Suppression_Pistol

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Projectile_Suppression_Pistol.Projectile_Suppression_Pistol_C
// 0x0000 (0x0060 - 0x0060)
class UProjectile_Suppression_Pistol_C final : public USQSuppressionInfo
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Projectile_Suppression_Pistol_C">();
	}
	static class UProjectile_Suppression_Pistol_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UProjectile_Suppression_Pistol_C>();
	}
};
static_assert(alignof(UProjectile_Suppression_Pistol_C) == 0x000008, "Wrong alignment on UProjectile_Suppression_Pistol_C");
static_assert(sizeof(UProjectile_Suppression_Pistol_C) == 0x000060, "Wrong size on UProjectile_Suppression_Pistol_C");

}

