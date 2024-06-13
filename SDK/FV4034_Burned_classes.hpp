#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FV4034_Burned

#include "Basic.hpp"

#include "FV4034_Knockedout_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass FV4034_Burned.FV4034_Burned_C
// 0x0000 (0x03E0 - 0x03E0)
class AFV4034_Burned_C final : public AFV4034_Knockedout_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"FV4034_Burned_C">();
	}
	static class AFV4034_Burned_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<AFV4034_Burned_C>();
	}
};
static_assert(alignof(AFV4034_Burned_C) == 0x000008, "Wrong alignment on AFV4034_Burned_C");
static_assert(sizeof(AFV4034_Burned_C) == 0x0003E0, "Wrong size on AFV4034_Burned_C");

}

