#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Techie_Wheel_Left

#include "Basic.hpp"

#include "Techie_Wheel_Right_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Techie_Wheel_Left.Techie_Wheel_Left_C
// 0x0000 (0x02C0 - 0x02C0)
class ATechie_Wheel_Left_C final : public ATechie_Wheel_Right_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Techie_Wheel_Left_C">();
	}
	static class ATechie_Wheel_Left_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATechie_Wheel_Left_C>();
	}
};
static_assert(alignof(ATechie_Wheel_Left_C) == 0x000008, "Wrong alignment on ATechie_Wheel_Left_C");
static_assert(sizeof(ATechie_Wheel_Left_C) == 0x0002C0, "Wrong size on ATechie_Wheel_Left_C");

}

