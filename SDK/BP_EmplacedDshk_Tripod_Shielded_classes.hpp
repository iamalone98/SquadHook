#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedDshk_Tripod_Shielded

#include "Basic.hpp"

#include "BP_EmplacedDshk_Tripod_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmplacedDshk_Tripod_Shielded.BP_EmplacedDshk_Tripod_Shielded_C
// 0x0010 (0x09F0 - 0x09E0)
class ABP_EmplacedDshk_Tripod_Shielded_C final : public ABP_EmplacedDshk_Tripod_C
{
public:
	class USQArmorMeshComponent*                  SQArmorMeshShield;                                 // 0x09E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmplacedDshk_Tripod_Shielded_C">();
	}
	static class ABP_EmplacedDshk_Tripod_Shielded_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_EmplacedDshk_Tripod_Shielded_C>();
	}
};
static_assert(alignof(ABP_EmplacedDshk_Tripod_Shielded_C) == 0x000010, "Wrong alignment on ABP_EmplacedDshk_Tripod_Shielded_C");
static_assert(sizeof(ABP_EmplacedDshk_Tripod_Shielded_C) == 0x0009F0, "Wrong size on ABP_EmplacedDshk_Tripod_Shielded_C");
static_assert(offsetof(ABP_EmplacedDshk_Tripod_Shielded_C, SQArmorMeshShield) == 0x0009E0, "Member 'ABP_EmplacedDshk_Tripod_Shielded_C::SQArmorMeshShield' has a wrong offset!");

}

