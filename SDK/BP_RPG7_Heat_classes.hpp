#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RPG7_Heat

#include "Basic.hpp"

#include "BP_RPG7_Parent_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RPG7_Heat.BP_RPG7_Heat_C
// 0x0000 (0x09F0 - 0x09F0)
class ABP_RPG7_Heat_C : public ABP_RPG7_Parent_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RPG7_Heat_C">();
	}
	static class ABP_RPG7_Heat_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RPG7_Heat_C>();
	}
};
static_assert(alignof(ABP_RPG7_Heat_C) == 0x000010, "Wrong alignment on ABP_RPG7_Heat_C");
static_assert(sizeof(ABP_RPG7_Heat_C) == 0x0009F0, "Wrong size on ABP_RPG7_Heat_C");

}
