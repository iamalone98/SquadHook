#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L94A1_coax

#include "Basic.hpp"

#include "BP_BTR80_RUS_PKT_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_L94A1_coax.BP_L94A1_coax_C
// 0x0000 (0x0C10 - 0x0C10)
class ABP_L94A1_coax_C final : public ABP_BTR80_RUS_PKT_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_L94A1_coax_C">();
	}
	static class ABP_L94A1_coax_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_L94A1_coax_C>();
	}
};
static_assert(alignof(ABP_L94A1_coax_C) == 0x000010, "Wrong alignment on ABP_L94A1_coax_C");
static_assert(sizeof(ABP_L94A1_coax_C) == 0x000C10, "Wrong size on ABP_L94A1_coax_C");

}

