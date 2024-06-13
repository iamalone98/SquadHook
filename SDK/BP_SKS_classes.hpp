#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SKS

#include "Basic.hpp"

#include "BP_GenericRifle_SingleLoad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SKS.BP_SKS_C
// 0x0000 (0x09B0 - 0x09B0)
#pragma pack(push, 0x1)
class alignas(0x10) ABP_SKS_C : public ABP_GenericRifle_SingleLoad_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SKS_C">();
	}
	static class ABP_SKS_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_SKS_C>();
	}
};
#pragma pack(pop)
static_assert(alignof(ABP_SKS_C) == 0x000010, "Wrong alignment on ABP_SKS_C");
static_assert(sizeof(ABP_SKS_C) == 0x0009B0, "Wrong size on ABP_SKS_C");

}

