#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: LPPV_Burn

#include "Basic.hpp"

#include "LPPV_Destroyed_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass LPPV_Burn.LPPV_Burn_C
// 0x0000 (0x03C8 - 0x03C8)
class ALPPV_Burn_C final : public ALPPV_Destroyed_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"LPPV_Burn_C">();
	}
	static class ALPPV_Burn_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ALPPV_Burn_C>();
	}
};
static_assert(alignof(ALPPV_Burn_C) == 0x000008, "Wrong alignment on ALPPV_Burn_C");
static_assert(sizeof(ALPPV_Burn_C) == 0x0003C8, "Wrong size on ALPPV_Burn_C");

}
