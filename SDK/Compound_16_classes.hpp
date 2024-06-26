#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Compound_16

#include "Basic.hpp"

#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass compound_16.compound_16_C
// 0x0018 (0x0240 - 0x0228)
class ACompound_16_C final : public AActor
{
public:
	class UStaticMeshComponent*                   SM_MERGED_compound_16_SM;                          // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        Audio1;                                            // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UArrowComponent*                        Arrow1;                                            // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"compound_16_C">();
	}
	static class ACompound_16_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ACompound_16_C>();
	}
};
static_assert(alignof(ACompound_16_C) == 0x000008, "Wrong alignment on ACompound_16_C");
static_assert(sizeof(ACompound_16_C) == 0x000240, "Wrong size on ACompound_16_C");
static_assert(offsetof(ACompound_16_C, SM_MERGED_compound_16_SM) == 0x000228, "Member 'ACompound_16_C::SM_MERGED_compound_16_SM' has a wrong offset!");
static_assert(offsetof(ACompound_16_C, Audio1) == 0x000230, "Member 'ACompound_16_C::Audio1' has a wrong offset!");
static_assert(offsetof(ACompound_16_C, Arrow1) == 0x000238, "Member 'ACompound_16_C::Arrow1' has a wrong offset!");

}

