#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SquadStateDataAmmoCrate

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SquadStateDataAmmoCrate.BP_SquadStateDataAmmoCrate_C
// 0x0000 (0x0160 - 0x0160)
class UBP_SquadStateDataAmmoCrate_C final : public USQSquadStateDataAmmoCrate
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SquadStateDataAmmoCrate_C">();
	}
	static class UBP_SquadStateDataAmmoCrate_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SquadStateDataAmmoCrate_C>();
	}
};
static_assert(alignof(UBP_SquadStateDataAmmoCrate_C) == 0x000008, "Wrong alignment on UBP_SquadStateDataAmmoCrate_C");
static_assert(sizeof(UBP_SquadStateDataAmmoCrate_C) == 0x000160, "Wrong size on UBP_SquadStateDataAmmoCrate_C");

}
