#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Dog_ambience_triggered2

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Dog_ambience_triggered2.BP_Dog_ambience_triggered2_C
// 0x0018 (0x0240 - 0x0228)
class ABP_Dog_ambience_triggered2_C final : public AActor
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0228(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBoxComponent*                          DummyPresetCollision;                              // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UAudioComponent*                        DogBarking;                                        // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Dog_ambience_triggered2(int32 EntryPoint);
	void OnComponentBeginOverlap_Event_0(class UPrimitiveComponent* OverlappedComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, int32 OtherBodyIndex, bool bFromSweep, const struct FHitResult& SweepResult);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Dog_ambience_triggered2_C">();
	}
	static class ABP_Dog_ambience_triggered2_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Dog_ambience_triggered2_C>();
	}
};
static_assert(alignof(ABP_Dog_ambience_triggered2_C) == 0x000008, "Wrong alignment on ABP_Dog_ambience_triggered2_C");
static_assert(sizeof(ABP_Dog_ambience_triggered2_C) == 0x000240, "Wrong size on ABP_Dog_ambience_triggered2_C");
static_assert(offsetof(ABP_Dog_ambience_triggered2_C, UberGraphFrame) == 0x000228, "Member 'ABP_Dog_ambience_triggered2_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_Dog_ambience_triggered2_C, DummyPresetCollision) == 0x000230, "Member 'ABP_Dog_ambience_triggered2_C::DummyPresetCollision' has a wrong offset!");
static_assert(offsetof(ABP_Dog_ambience_triggered2_C, DogBarking) == 0x000238, "Member 'ABP_Dog_ambience_triggered2_C::DogBarking' has a wrong offset!");

}

