#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tracks_BMP_Right

#include "Basic.hpp"

#include "Tracks_BMP_Left_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Tracks_BMP_Right.Tracks_BMP_Right_C
// 0x0000 (0x0320 - 0x0320)
class ATracks_BMP_Right_C final : public ATracks_BMP_Left_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Tracks_BMP_Right_C">();
	}
	static class ATracks_BMP_Right_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATracks_BMP_Right_C>();
	}
};
static_assert(alignof(ATracks_BMP_Right_C) == 0x000008, "Wrong alignment on ATracks_BMP_Right_C");
static_assert(sizeof(ATracks_BMP_Right_C) == 0x000320, "Wrong size on ATracks_BMP_Right_C");

}

