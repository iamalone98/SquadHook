#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MaterialEffects_Mortar_Smoke

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_MaterialEffects_Mortar_Smoke.BP_MaterialEffects_Mortar_Smoke_C
// 0x0000 (0x0080 - 0x0080)
class UBP_MaterialEffects_Mortar_Smoke_C final : public USQPhysicalMaterialEffects
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MaterialEffects_Mortar_Smoke_C">();
	}
	static class UBP_MaterialEffects_Mortar_Smoke_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MaterialEffects_Mortar_Smoke_C>();
	}
};
static_assert(alignof(UBP_MaterialEffects_Mortar_Smoke_C) == 0x000008, "Wrong alignment on UBP_MaterialEffects_Mortar_Smoke_C");
static_assert(sizeof(UBP_MaterialEffects_Mortar_Smoke_C) == 0x000080, "Wrong size on UBP_MaterialEffects_Mortar_Smoke_C");

}

