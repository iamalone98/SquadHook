#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedDshk_Shield

#include "Basic.hpp"

#include "BP_EmplacedDshk_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmplacedDshk_Shield.BP_EmplacedDshk_Shield_C
// 0x0010 (0x0D40 - 0x0D30)
class ABP_EmplacedDshk_Shield_C final : public ABP_EmplacedDshk_C
{
public:
	class UStaticMeshComponent*                   Shield;                                            // 0x0D30(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmplacedDshk_Shield_C">();
	}
	static class ABP_EmplacedDshk_Shield_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_EmplacedDshk_Shield_C>();
	}
};
static_assert(alignof(ABP_EmplacedDshk_Shield_C) == 0x000010, "Wrong alignment on ABP_EmplacedDshk_Shield_C");
static_assert(sizeof(ABP_EmplacedDshk_Shield_C) == 0x000D40, "Wrong size on ABP_EmplacedDshk_Shield_C");
static_assert(offsetof(ABP_EmplacedDshk_Shield_C, Shield) == 0x000D30, "Member 'ABP_EmplacedDshk_Shield_C::Shield' has a wrong offset!");

}

