#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Generic_FieldDressing_Medic

#include "Basic.hpp"

#include "BP_Generic_FieldDressing_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Generic_FieldDressing_Medic.BP_Generic_FieldDressing_Medic_C
// 0x0000 (0x0538 - 0x0538)
class ABP_Generic_FieldDressing_Medic_C final : public ABP_Generic_FieldDressing_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Generic_FieldDressing_Medic_C">();
	}
	static class ABP_Generic_FieldDressing_Medic_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Generic_FieldDressing_Medic_C>();
	}
};
static_assert(alignof(ABP_Generic_FieldDressing_Medic_C) == 0x000008, "Wrong alignment on ABP_Generic_FieldDressing_Medic_C");
static_assert(sizeof(ABP_Generic_FieldDressing_Medic_C) == 0x000538, "Wrong size on ABP_Generic_FieldDressing_Medic_C");

}
