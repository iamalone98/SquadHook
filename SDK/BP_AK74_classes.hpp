#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_AK74

#include "Basic.hpp"

#include "BP_GenericRifle_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_AK74.BP_AK74_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_AK74_C : public ABP_GenericRifle_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_AK74_C">();
	}
	static class ABP_AK74_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_AK74_C>();
	}
};
static_assert(alignof(ABP_AK74_C) == 0x000010, "Wrong alignment on ABP_AK74_C");
static_assert(sizeof(ABP_AK74_C) == 0x0009A0, "Wrong size on ABP_AK74_C");

}
