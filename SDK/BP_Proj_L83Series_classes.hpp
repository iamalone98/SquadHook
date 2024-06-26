#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Proj_L83Series

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_Grenade_Proj_Smoke_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Proj_L83Series.BP_Proj_L83Series_C
// 0x0018 (0x0530 - 0x0518)
class ABP_Proj_L83Series_C final : public ABP_Grenade_Proj_Smoke_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Proj_L83Series_C;                // 0x0518(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               SpoonEject;                                        // 0x0520(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        SmokePop;                                          // 0x0528(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Proj_L83Series(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Proj_L83Series_C">();
	}
	static class ABP_Proj_L83Series_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Proj_L83Series_C>();
	}
};
static_assert(alignof(ABP_Proj_L83Series_C) == 0x000008, "Wrong alignment on ABP_Proj_L83Series_C");
static_assert(sizeof(ABP_Proj_L83Series_C) == 0x000530, "Wrong size on ABP_Proj_L83Series_C");
static_assert(offsetof(ABP_Proj_L83Series_C, UberGraphFrame_BP_Proj_L83Series_C) == 0x000518, "Member 'ABP_Proj_L83Series_C::UberGraphFrame_BP_Proj_L83Series_C' has a wrong offset!");
static_assert(offsetof(ABP_Proj_L83Series_C, SpoonEject) == 0x000520, "Member 'ABP_Proj_L83Series_C::SpoonEject' has a wrong offset!");
static_assert(offsetof(ABP_Proj_L83Series_C, SmokePop) == 0x000528, "Member 'ABP_Proj_L83Series_C::SmokePop' has a wrong offset!");

}

