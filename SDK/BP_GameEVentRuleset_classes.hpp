#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GameEVentRuleset

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GameEVentRuleset.BP_GameEventRuleset_C
// 0x0008 (0x0268 - 0x0260)
class ABP_GameEventRuleset_C final : public ASQGameEventRuleset
{
public:
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0260(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GameEventRuleset_C">();
	}
	static class ABP_GameEventRuleset_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GameEventRuleset_C>();
	}
};
static_assert(alignof(ABP_GameEventRuleset_C) == 0x000008, "Wrong alignment on ABP_GameEventRuleset_C");
static_assert(sizeof(ABP_GameEventRuleset_C) == 0x000268, "Wrong size on ABP_GameEventRuleset_C");
static_assert(offsetof(ABP_GameEventRuleset_C, DefaultSceneRoot) == 0x000260, "Member 'ABP_GameEventRuleset_C::DefaultSceneRoot' has a wrong offset!");

}

