#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Explosion_Suppression_C4

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Explosion_Suppression_C4.Explosion_Suppression_C4_C
// 0x0000 (0x0078 - 0x0078)
class UExplosion_Suppression_C4_C final : public USQRadialSuppressionInfo
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Explosion_Suppression_C4_C">();
	}
	static class UExplosion_Suppression_C4_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UExplosion_Suppression_C4_C>();
	}
};
static_assert(alignof(UExplosion_Suppression_C4_C) == 0x000008, "Wrong alignment on UExplosion_Suppression_C4_C");
static_assert(sizeof(UExplosion_Suppression_C4_C) == 0x000078, "Wrong size on UExplosion_Suppression_C4_C");

}
