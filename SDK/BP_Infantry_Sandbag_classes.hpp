#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Infantry_Sandbag

#include "Basic.hpp"

#include "BP_GenericEquippableItem_Deployable_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Infantry_Sandbag.BP_Infantry_Sandbag_C
// 0x0000 (0x0498 - 0x0498)
class ABP_Infantry_Sandbag_C : public ABP_GenericEquippableItem_Deployable_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Infantry_Sandbag_C">();
	}
	static class ABP_Infantry_Sandbag_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Infantry_Sandbag_C>();
	}
};
static_assert(alignof(ABP_Infantry_Sandbag_C) == 0x000008, "Wrong alignment on ABP_Infantry_Sandbag_C");
static_assert(sizeof(ABP_Infantry_Sandbag_C) == 0x000498, "Wrong size on ABP_Infantry_Sandbag_C");

}

