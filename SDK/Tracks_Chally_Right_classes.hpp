#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tracks_Chally_Right

#include "Basic.hpp"

#include "Tracks_Chally_Left_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Tracks_Chally_Right.Tracks_Chally_Right_C
// 0x0000 (0x0338 - 0x0338)
class ATracks_Chally_Right_C final : public ATracks_Chally_Left_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Tracks_Chally_Right_C">();
	}
	static class ATracks_Chally_Right_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATracks_Chally_Right_C>();
	}
};
static_assert(alignof(ATracks_Chally_Right_C) == 0x000008, "Wrong alignment on ATracks_Chally_Right_C");
static_assert(sizeof(ATracks_Chally_Right_C) == 0x000338, "Wrong size on ATracks_Chally_Right_C");

}
