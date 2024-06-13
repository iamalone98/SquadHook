#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SmokeGenerator_Tracked

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass SmokeGenerator_Tracked.SmokeGenerator_Tracked_C
// 0x0040 (0x0C40 - 0x0C00)
class ASmokeGenerator_Tracked_C final : public ASQVehicleSmokeGenerator
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0C00(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UParticleSystem*                        SmokeEffect;                                       // 0x0C08(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class FName>                           WheelFxCachedBoneNames;                            // 0x0C10(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<struct FParticleSysParam>              WheelFxCachedParams;                               // 0x0C20(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	class UClass*                                 LastingEffect;                                     // 0x0C30(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         LifetimeAfterDestruction;                          // 0x0C38(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_SmokeGenerator_Tracked(int32 EntryPoint);
	void ReceiveDestroyed();
	void SetupParticleSystem(class AActor* OwnerActor);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SmokeGenerator_Tracked_C">();
	}
	static class ASmokeGenerator_Tracked_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ASmokeGenerator_Tracked_C>();
	}
};
static_assert(alignof(ASmokeGenerator_Tracked_C) == 0x000010, "Wrong alignment on ASmokeGenerator_Tracked_C");
static_assert(sizeof(ASmokeGenerator_Tracked_C) == 0x000C40, "Wrong size on ASmokeGenerator_Tracked_C");
static_assert(offsetof(ASmokeGenerator_Tracked_C, UberGraphFrame) == 0x000C00, "Member 'ASmokeGenerator_Tracked_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ASmokeGenerator_Tracked_C, SmokeEffect) == 0x000C08, "Member 'ASmokeGenerator_Tracked_C::SmokeEffect' has a wrong offset!");
static_assert(offsetof(ASmokeGenerator_Tracked_C, WheelFxCachedBoneNames) == 0x000C10, "Member 'ASmokeGenerator_Tracked_C::WheelFxCachedBoneNames' has a wrong offset!");
static_assert(offsetof(ASmokeGenerator_Tracked_C, WheelFxCachedParams) == 0x000C20, "Member 'ASmokeGenerator_Tracked_C::WheelFxCachedParams' has a wrong offset!");
static_assert(offsetof(ASmokeGenerator_Tracked_C, LastingEffect) == 0x000C30, "Member 'ASmokeGenerator_Tracked_C::LastingEffect' has a wrong offset!");
static_assert(offsetof(ASmokeGenerator_Tracked_C, LifetimeAfterDestruction) == 0x000C38, "Member 'ASmokeGenerator_Tracked_C::LifetimeAfterDestruction' has a wrong offset!");

}
