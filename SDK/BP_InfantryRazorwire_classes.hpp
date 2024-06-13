#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_InfantryRazorwire

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_InfantryRazorwire.BP_InfantryRazorwire_C
// 0x00A0 (0x04F0 - 0x0450)
class ABP_InfantryRazorwire_C final : public ASQDeployableItem
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0450(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   StaticMesh21;                                      // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQPainCausingVolumeComponent*          SQPainCausingVolume2;                              // 0x0460(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQMovementAdjustmentComponent*         SQMovementAdjustment2;                             // 0x0468(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh26;                                      // 0x0470(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh25;                                      // 0x0478(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh24;                                      // 0x0480(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh23;                                      // 0x0488(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh22;                                      // 0x0490(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh16;                                      // 0x0498(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQMovementAdjustmentComponent*         SQMovementAdjustment1;                             // 0x04A0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQPainCausingVolumeComponent*          SQPainCausingVolume1;                              // 0x04A8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh20;                                      // 0x04B0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh19;                                      // 0x04B8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh18;                                      // 0x04C0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh17;                                      // 0x04C8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh15;                                      // 0x04D0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   StaticMesh14;                                      // 0x04D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          InteractZone;                                      // 0x04E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          ConstructionZone;                                  // 0x04E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_InfantryRazorwire(int32 EntryPoint);
	void ReceiveDestroyed();
	void RemovedFromPlayersPlacedList();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_InfantryRazorwire_C">();
	}
	static class ABP_InfantryRazorwire_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_InfantryRazorwire_C>();
	}
};
static_assert(alignof(ABP_InfantryRazorwire_C) == 0x000008, "Wrong alignment on ABP_InfantryRazorwire_C");
static_assert(sizeof(ABP_InfantryRazorwire_C) == 0x0004F0, "Wrong size on ABP_InfantryRazorwire_C");
static_assert(offsetof(ABP_InfantryRazorwire_C, UberGraphFrame) == 0x000450, "Member 'ABP_InfantryRazorwire_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh21) == 0x000458, "Member 'ABP_InfantryRazorwire_C::StaticMesh21' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, SQPainCausingVolume2) == 0x000460, "Member 'ABP_InfantryRazorwire_C::SQPainCausingVolume2' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, SQMovementAdjustment2) == 0x000468, "Member 'ABP_InfantryRazorwire_C::SQMovementAdjustment2' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh26) == 0x000470, "Member 'ABP_InfantryRazorwire_C::StaticMesh26' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh25) == 0x000478, "Member 'ABP_InfantryRazorwire_C::StaticMesh25' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh24) == 0x000480, "Member 'ABP_InfantryRazorwire_C::StaticMesh24' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh23) == 0x000488, "Member 'ABP_InfantryRazorwire_C::StaticMesh23' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh22) == 0x000490, "Member 'ABP_InfantryRazorwire_C::StaticMesh22' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh16) == 0x000498, "Member 'ABP_InfantryRazorwire_C::StaticMesh16' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, SQMovementAdjustment1) == 0x0004A0, "Member 'ABP_InfantryRazorwire_C::SQMovementAdjustment1' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, SQPainCausingVolume1) == 0x0004A8, "Member 'ABP_InfantryRazorwire_C::SQPainCausingVolume1' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh20) == 0x0004B0, "Member 'ABP_InfantryRazorwire_C::StaticMesh20' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh19) == 0x0004B8, "Member 'ABP_InfantryRazorwire_C::StaticMesh19' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh18) == 0x0004C0, "Member 'ABP_InfantryRazorwire_C::StaticMesh18' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh17) == 0x0004C8, "Member 'ABP_InfantryRazorwire_C::StaticMesh17' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh15) == 0x0004D0, "Member 'ABP_InfantryRazorwire_C::StaticMesh15' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, StaticMesh14) == 0x0004D8, "Member 'ABP_InfantryRazorwire_C::StaticMesh14' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, InteractZone) == 0x0004E0, "Member 'ABP_InfantryRazorwire_C::InteractZone' has a wrong offset!");
static_assert(offsetof(ABP_InfantryRazorwire_C, ConstructionZone) == 0x0004E8, "Member 'ABP_InfantryRazorwire_C::ConstructionZone' has a wrong offset!");

}
