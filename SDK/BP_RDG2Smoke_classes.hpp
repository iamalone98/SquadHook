#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RDG2Smoke

#include "Basic.hpp"

#include "BP_GenericSmokeGrenade_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RDG2Smoke.BP_RDG2Smoke_C
// 0x0000 (0x0580 - 0x0580)
class ABP_RDG2Smoke_C : public ABP_GenericSmokeGrenade_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RDG2Smoke_C">();
	}
	static class ABP_RDG2Smoke_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RDG2Smoke_C>();
	}
};
static_assert(alignof(ABP_RDG2Smoke_C) == 0x000008, "Wrong alignment on ABP_RDG2Smoke_C");
static_assert(sizeof(ABP_RDG2Smoke_C) == 0x000580, "Wrong size on ABP_RDG2Smoke_C");

}
