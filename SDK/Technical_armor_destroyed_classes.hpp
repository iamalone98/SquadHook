#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Technical_armor_destroyed

#include "Basic.hpp"

#include "Technical_destroyed_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass Technical_armor_destroyed.Technical_armor_destroyed_C
// 0x0000 (0x03C8 - 0x03C8)
class ATechnical_armor_destroyed_C final : public ATechnical_destroyed_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Technical_armor_destroyed_C">();
	}
	static class ATechnical_armor_destroyed_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ATechnical_armor_destroyed_C>();
	}
};
static_assert(alignof(ATechnical_armor_destroyed_C) == 0x000008, "Wrong alignment on ATechnical_armor_destroyed_C");
static_assert(sizeof(ATechnical_armor_destroyed_C) == 0x0003C8, "Wrong size on ATechnical_armor_destroyed_C");

}
