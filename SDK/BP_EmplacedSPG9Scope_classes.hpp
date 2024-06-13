#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedSPG9Scope

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_EmplacedSPG9_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C
// 0x0040 (0x0D80 - 0x0D40)
class ABP_EmplacedSPG9Scope_C final : public ABP_EmplacedSPG9_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_EmplacedSPG9Scope_C;             // 0x0D40(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   Scope;                                             // 0x0D48(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_0__Direction_89E5335E475A036BED3B15B05B2ED2A0; // 0x0D50(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4FB0[0x7];                                     // 0x0D51(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_0;                                        // 0x0D58(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 ReticleClass;                                      // 0x0D60(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       OverlayCamera;                                     // 0x0D68(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            Last_PC;                                           // 0x0D70(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQHUD*                                 Last_HUD;                                          // 0x0D78(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_EmplacedSPG9Scope(int32 EntryPoint);
	void RemoveADS();
	void CUnpossessed();
	void CPossessed();
	void ReceiveBeginPlay();
	void BlueprintOnZoom(bool bNewZoom);
	void Timeline_0__UpdateFunc();
	void Timeline_0__FinishedFunc();
	void UserConstructionScript();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmplacedSPG9Scope_C">();
	}
	static class ABP_EmplacedSPG9Scope_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_EmplacedSPG9Scope_C>();
	}
};
static_assert(alignof(ABP_EmplacedSPG9Scope_C) == 0x000010, "Wrong alignment on ABP_EmplacedSPG9Scope_C");
static_assert(sizeof(ABP_EmplacedSPG9Scope_C) == 0x000D80, "Wrong size on ABP_EmplacedSPG9Scope_C");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, UberGraphFrame_BP_EmplacedSPG9Scope_C) == 0x000D40, "Member 'ABP_EmplacedSPG9Scope_C::UberGraphFrame_BP_EmplacedSPG9Scope_C' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, Scope) == 0x000D48, "Member 'ABP_EmplacedSPG9Scope_C::Scope' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, Timeline_0__Direction_89E5335E475A036BED3B15B05B2ED2A0) == 0x000D50, "Member 'ABP_EmplacedSPG9Scope_C::Timeline_0__Direction_89E5335E475A036BED3B15B05B2ED2A0' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, Timeline_0) == 0x000D58, "Member 'ABP_EmplacedSPG9Scope_C::Timeline_0' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, ReticleClass) == 0x000D60, "Member 'ABP_EmplacedSPG9Scope_C::ReticleClass' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, OverlayCamera) == 0x000D68, "Member 'ABP_EmplacedSPG9Scope_C::OverlayCamera' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, Last_PC) == 0x000D70, "Member 'ABP_EmplacedSPG9Scope_C::Last_PC' has a wrong offset!");
static_assert(offsetof(ABP_EmplacedSPG9Scope_C, Last_HUD) == 0x000D78, "Member 'ABP_EmplacedSPG9Scope_C::Last_HUD' has a wrong offset!");

}
