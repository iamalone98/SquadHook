#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CableDrum

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_CableDrum.BP_CableDrum_C
// 0x0030 (0x0270 - 0x0240)
class ABP_CableDrum_C : public ASQRandomizer
{
public:
	class UStaticMeshComponent*                   CableDrum;                                         // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           NonMinusRandomised_Colour;                         // 0x0248(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bUseRandomiser;                                    // 0x0258(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4B8F[0x7];                                     // 0x0259(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FLinearColor>                   RandomColourChoices;                               // 0x0260(0x0010)(Edit, BlueprintVisible)

public:
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_CableDrum_C">();
	}
	static class ABP_CableDrum_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_CableDrum_C>();
	}
};
static_assert(alignof(ABP_CableDrum_C) == 0x000008, "Wrong alignment on ABP_CableDrum_C");
static_assert(sizeof(ABP_CableDrum_C) == 0x000270, "Wrong size on ABP_CableDrum_C");
static_assert(offsetof(ABP_CableDrum_C, CableDrum) == 0x000240, "Member 'ABP_CableDrum_C::CableDrum' has a wrong offset!");
static_assert(offsetof(ABP_CableDrum_C, NonMinusRandomised_Colour) == 0x000248, "Member 'ABP_CableDrum_C::NonMinusRandomised_Colour' has a wrong offset!");
static_assert(offsetof(ABP_CableDrum_C, bUseRandomiser) == 0x000258, "Member 'ABP_CableDrum_C::bUseRandomiser' has a wrong offset!");
static_assert(offsetof(ABP_CableDrum_C, RandomColourChoices) == 0x000260, "Member 'ABP_CableDrum_C::RandomColourChoices' has a wrong offset!");

}

