#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericRocketLauncher

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_Weapon2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericRocketLauncher.BP_GenericRocketLauncher_C
// 0x0050 (0x09F0 - 0x09A0)
#pragma pack(push, 0x1)
class alignas(0x10) ABP_GenericRocketLauncher_C : public ABP_Weapon2_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_GenericRocketLauncher_C;         // 0x09A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystemComponent*               MuzzleFlashRearComponent3P;                        // 0x09A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UChildActorComponent*                   BackBlastComponent3P;                              // 0x09B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               MuzzleFlashRearComponent1P;                        // 0x09B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQBlastComponent*                      SquadBlast;                                        // 0x09C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UChildActorComponent*                   BackBlastComponent1P;                              // 0x09C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class FName                                   BackblastSocket;                                   // 0x09D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        BackblastEffect1P;                                 // 0x09D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        BackblastEffect3P;                                 // 0x09E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericRocketLauncher(int32 EntryPoint);
	void BlueprintOnFire(const struct FVector& Origin);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericRocketLauncher_C">();
	}
	static class ABP_GenericRocketLauncher_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericRocketLauncher_C>();
	}
};
#pragma pack(pop)
static_assert(alignof(ABP_GenericRocketLauncher_C) == 0x000010, "Wrong alignment on ABP_GenericRocketLauncher_C");
static_assert(sizeof(ABP_GenericRocketLauncher_C) == 0x0009F0, "Wrong size on ABP_GenericRocketLauncher_C");
static_assert(offsetof(ABP_GenericRocketLauncher_C, UberGraphFrame_BP_GenericRocketLauncher_C) == 0x0009A0, "Member 'ABP_GenericRocketLauncher_C::UberGraphFrame_BP_GenericRocketLauncher_C' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, MuzzleFlashRearComponent3P) == 0x0009A8, "Member 'ABP_GenericRocketLauncher_C::MuzzleFlashRearComponent3P' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, BackBlastComponent3P) == 0x0009B0, "Member 'ABP_GenericRocketLauncher_C::BackBlastComponent3P' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, MuzzleFlashRearComponent1P) == 0x0009B8, "Member 'ABP_GenericRocketLauncher_C::MuzzleFlashRearComponent1P' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, SquadBlast) == 0x0009C0, "Member 'ABP_GenericRocketLauncher_C::SquadBlast' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, BackBlastComponent1P) == 0x0009C8, "Member 'ABP_GenericRocketLauncher_C::BackBlastComponent1P' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, BackblastSocket) == 0x0009D0, "Member 'ABP_GenericRocketLauncher_C::BackblastSocket' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, BackblastEffect1P) == 0x0009D8, "Member 'ABP_GenericRocketLauncher_C::BackblastEffect1P' has a wrong offset!");
static_assert(offsetof(ABP_GenericRocketLauncher_C, BackblastEffect3P) == 0x0009E0, "Member 'ABP_GenericRocketLauncher_C::BackblastEffect3P' has a wrong offset!");

}

