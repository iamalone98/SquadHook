#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RocketBlast

#include "Basic.hpp"

#include "BP_CannonBlast_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RocketBlast.BP_RocketBlast_C
// 0x0000 (0x00E0 - 0x00E0)
class UBP_RocketBlast_C final : public UBP_CannonBlast_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RocketBlast_C">();
	}
	static class UBP_RocketBlast_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_RocketBlast_C>();
	}
};
static_assert(alignof(UBP_RocketBlast_C) == 0x000008, "Wrong alignment on UBP_RocketBlast_C");
static_assert(sizeof(UBP_RocketBlast_C) == 0x0000E0, "Wrong size on UBP_RocketBlast_C");

}

