#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L110A2

#include "Basic.hpp"

#include "BP_M249_Pip_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_L110A2.BP_L110A2_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_L110A2_C : public ABP_M249_Pip_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_L110A2_C">();
	}
	static class ABP_L110A2_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_L110A2_C>();
	}
};
static_assert(alignof(ABP_L110A2_C) == 0x000010, "Wrong alignment on ABP_L110A2_C");
static_assert(sizeof(ABP_L110A2_C) == 0x0009A0, "Wrong size on ABP_L110A2_C");

}

