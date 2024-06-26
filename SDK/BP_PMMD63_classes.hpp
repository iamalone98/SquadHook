#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_PMMD63

#include "Basic.hpp"

#include "BP_AKM_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_PMMD63.BP_PMMD63_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_PMMD63_C : public ABP_AKM_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_PMMD63_C">();
	}
	static class ABP_PMMD63_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_PMMD63_C>();
	}
};
static_assert(alignof(ABP_PMMD63_C) == 0x000010, "Wrong alignment on ABP_PMMD63_C");
static_assert(sizeof(ABP_PMMD63_C) == 0x0009A0, "Wrong size on ABP_PMMD63_C");

}

