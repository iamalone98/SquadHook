#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ForwardBaseSpawn

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_ForwardBaseSpawn.BP_ForwardBaseSpawn_C
// 0x0000 (0x0400 - 0x0400)
class ABP_ForwardBaseSpawn_C final : public ASQGameSpawn
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_ForwardBaseSpawn_C">();
	}
	static class ABP_ForwardBaseSpawn_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_ForwardBaseSpawn_C>();
	}
};
static_assert(alignof(ABP_ForwardBaseSpawn_C) == 0x000008, "Wrong alignment on ABP_ForwardBaseSpawn_C");
static_assert(sizeof(ABP_ForwardBaseSpawn_C) == 0x000400, "Wrong size on ABP_ForwardBaseSpawn_C");

}
