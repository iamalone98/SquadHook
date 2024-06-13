#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_afg_house_barn01

#include "Basic.hpp"

#include "ReverbVolumeSettings_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_afg_house_barn01.BP_afg_house_barn01_C
// 0x0030 (0x0258 - 0x0228)
class ABP_afg_house_barn01_C final : public AActor
{
public:
	class UStaticMeshComponent*                   StaticMesh1;                                       // 0x0228(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	struct FReverbVolumeSettings                  ReverbTightOpen;                                   // 0x0230(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_afg_house_barn01_C">();
	}
	static class ABP_afg_house_barn01_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_afg_house_barn01_C>();
	}
};
static_assert(alignof(ABP_afg_house_barn01_C) == 0x000008, "Wrong alignment on ABP_afg_house_barn01_C");
static_assert(sizeof(ABP_afg_house_barn01_C) == 0x000258, "Wrong size on ABP_afg_house_barn01_C");
static_assert(offsetof(ABP_afg_house_barn01_C, StaticMesh1) == 0x000228, "Member 'ABP_afg_house_barn01_C::StaticMesh1' has a wrong offset!");
static_assert(offsetof(ABP_afg_house_barn01_C, ReverbTightOpen) == 0x000230, "Member 'ABP_afg_house_barn01_C::ReverbTightOpen' has a wrong offset!");

}

