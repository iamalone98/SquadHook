#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_M240

#include "Basic.hpp"

#include "BP_GenericMachineGun_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_M240.BP_M240_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_M240_C : public ABP_GenericMachineGun_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_M240_C">();
	}
	static class ABP_M240_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_M240_C>();
	}
};
static_assert(alignof(ABP_M240_C) == 0x000010, "Wrong alignment on ABP_M240_C");
static_assert(sizeof(ABP_M240_C) == 0x0009A0, "Wrong size on ABP_M240_C");

}

