#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericPistol

#include "Basic.hpp"

#include "BP_Weapon2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericPistol.BP_GenericPistol_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_GenericPistol_C : public ABP_Weapon2_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericPistol_C">();
	}
	static class ABP_GenericPistol_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericPistol_C>();
	}
};
static_assert(alignof(ABP_GenericPistol_C) == 0x000010, "Wrong alignment on ABP_GenericPistol_C");
static_assert(sizeof(ABP_GenericPistol_C) == 0x0009A0, "Wrong size on ABP_GenericPistol_C");

}
