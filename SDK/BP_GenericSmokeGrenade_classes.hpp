#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericSmokeGrenade

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericSmokeGrenade.BP_GenericSmokeGrenade_C
// 0x0000 (0x0580 - 0x0580)
class ABP_GenericSmokeGrenade_C : public ASQSmokeGrenade
{
public:
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericSmokeGrenade_C">();
	}
	static class ABP_GenericSmokeGrenade_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericSmokeGrenade_C>();
	}
};
static_assert(alignof(ABP_GenericSmokeGrenade_C) == 0x000008, "Wrong alignment on ABP_GenericSmokeGrenade_C");
static_assert(sizeof(ABP_GenericSmokeGrenade_C) == 0x000580, "Wrong size on ABP_GenericSmokeGrenade_C");

}

