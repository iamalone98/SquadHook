#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RKG3Antitank

#include "Basic.hpp"

#include "BP_GenericGrenade_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RKG3Antitank.BP_RKG3Antitank_C
// 0x0000 (0x0570 - 0x0570)
class ABP_RKG3Antitank_C final : public ABP_GenericGrenade_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RKG3Antitank_C">();
	}
	static class ABP_RKG3Antitank_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RKG3Antitank_C>();
	}
};
static_assert(alignof(ABP_RKG3Antitank_C) == 0x000008, "Wrong alignment on ABP_RKG3Antitank_C");
static_assert(sizeof(ABP_RKG3Antitank_C) == 0x000570, "Wrong size on ABP_RKG3Antitank_C");

}
