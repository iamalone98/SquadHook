#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: AmmoWep_150

#include "Basic.hpp"

#include "AmmoResourceWeapon_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass AmmoWep_150.AmmoWep_150_C
// 0x0000 (0x0268 - 0x0268)
class AAmmoWep_150_C final : public AAmmoResourceWeapon_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"AmmoWep_150_C">();
	}
	static class AAmmoWep_150_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AAmmoWep_150_C>();
	}
};
static_assert(alignof(AAmmoWep_150_C) == 0x000008, "Wrong alignment on AAmmoWep_150_C");
static_assert(sizeof(AAmmoWep_150_C) == 0x000268, "Wrong size on AAmmoWep_150_C");

}

