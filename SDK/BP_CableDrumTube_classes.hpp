#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CableDrumTube

#include "Basic.hpp"

#include "BP_CableDrum_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_CableDrumTube.BP_CableDrumTube_C
// 0x0008 (0x0278 - 0x0270)
class ABP_CableDrumTube_C final : public ABP_CableDrum_C
{
public:
	class UStaticMeshComponent*                   Tubing;                                            // 0x0270(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_CableDrumTube_C">();
	}
	static class ABP_CableDrumTube_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_CableDrumTube_C>();
	}
};
static_assert(alignof(ABP_CableDrumTube_C) == 0x000008, "Wrong alignment on ABP_CableDrumTube_C");
static_assert(sizeof(ABP_CableDrumTube_C) == 0x000278, "Wrong size on ABP_CableDrumTube_C");
static_assert(offsetof(ABP_CableDrumTube_C, Tubing) == 0x000270, "Member 'ABP_CableDrumTube_C::Tubing' has a wrong offset!");

}

