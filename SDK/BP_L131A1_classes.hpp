#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L131A1

#include "Basic.hpp"

#include "BP_GenericPistol_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_L131A1.BP_L131A1_C
// 0x0000 (0x09A0 - 0x09A0)
class ABP_L131A1_C : public ABP_GenericPistol_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_L131A1_C">();
	}
	static class ABP_L131A1_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_L131A1_C>();
	}
};
static_assert(alignof(ABP_L131A1_C) == 0x000010, "Wrong alignment on ABP_L131A1_C");
static_assert(sizeof(ABP_L131A1_C) == 0x0009A0, "Wrong size on ABP_L131A1_C");

}
