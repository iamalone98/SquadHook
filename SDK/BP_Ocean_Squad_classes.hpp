#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ocean_Squad

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_Ocean_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Ocean_Squad.BP_Ocean_Squad_C
// 0x0010 (0x0348 - 0x0338)
class ABP_Ocean_Squad_C final : public ABP_Ocean_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Ocean_Squad_C;                   // 0x0338(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	bool                                          VisualizePostprocessBound;                         // 0x0340(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)

public:
	void ExecuteUbergraph_BP_Ocean_Squad(int32 EntryPoint);
	void SetMiniMapMask();
	void VisualizeWaterLinePostProcessBound();
	void ReceiveTick(float DeltaSeconds);
	void ReceiveBeginPlay();
	float GetActorImmersionDepth(const class AActor* QueryingActor);

	bool HasValidProjectileOverlap(class UPrimitiveComponent* OverlappedComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, int32 OtherBodyIndex, bool bFromSweep, const struct FHitResult& SweepResult) const;
	bool HasValidProjectileHit(const class AActor* ProjectileOwner, const struct FHitResult& InHit) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Ocean_Squad_C">();
	}
	static class ABP_Ocean_Squad_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Ocean_Squad_C>();
	}
};
static_assert(alignof(ABP_Ocean_Squad_C) == 0x000008, "Wrong alignment on ABP_Ocean_Squad_C");
static_assert(sizeof(ABP_Ocean_Squad_C) == 0x000348, "Wrong size on ABP_Ocean_Squad_C");
static_assert(offsetof(ABP_Ocean_Squad_C, UberGraphFrame_BP_Ocean_Squad_C) == 0x000338, "Member 'ABP_Ocean_Squad_C::UberGraphFrame_BP_Ocean_Squad_C' has a wrong offset!");
static_assert(offsetof(ABP_Ocean_Squad_C, VisualizePostprocessBound) == 0x000340, "Member 'ABP_Ocean_Squad_C::VisualizePostprocessBound' has a wrong offset!");

}
