#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Kinetic_DamageType

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Kinetic_DamageType.BP_Kinetic_DamageType_C
// 0x0000 (0x0048 - 0x0048)
class UBP_Kinetic_DamageType_C final : public USQDamageType
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Kinetic_DamageType_C">();
	}
	static class UBP_Kinetic_DamageType_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Kinetic_DamageType_C>();
	}
};
static_assert(alignof(UBP_Kinetic_DamageType_C) == 0x000008, "Wrong alignment on UBP_Kinetic_DamageType_C");
static_assert(sizeof(UBP_Kinetic_DamageType_C) == 0x000048, "Wrong size on UBP_Kinetic_DamageType_C");

}

