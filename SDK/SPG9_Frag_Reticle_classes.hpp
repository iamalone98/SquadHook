#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SPG9_Frag_Reticle

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SPG9_Frag_Reticle.SPG9_Frag_Reticle_C
// 0x0050 (0x02F0 - 0x02A0)
class USPG9_Frag_Reticle_C final : public USQVehicleViewWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Tunnel;                                            // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 UnzoomedImage;                                     // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 ZoomedImage;                                       // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	struct FRotator                               LastRot;                                           // 0x02C0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	float                                         OffsetX;                                           // 0x02CC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               RotInterp;                                         // 0x02D0(0x000C)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3315[0x4];                                     // 0x02DC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 ParentWeapon;                                      // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OffsetY;                                           // 0x02E8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_SPG9_Frag_Reticle(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	void TunnelOffset(float RangeOfMotion, float Multiplier, float InterpSpeed, class UWidget* TunnelImg, class UWidget* Reticle);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SPG9_Frag_Reticle_C">();
	}
	static class USPG9_Frag_Reticle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USPG9_Frag_Reticle_C>();
	}
};
static_assert(alignof(USPG9_Frag_Reticle_C) == 0x000008, "Wrong alignment on USPG9_Frag_Reticle_C");
static_assert(sizeof(USPG9_Frag_Reticle_C) == 0x0002F0, "Wrong size on USPG9_Frag_Reticle_C");
static_assert(offsetof(USPG9_Frag_Reticle_C, UberGraphFrame) == 0x0002A0, "Member 'USPG9_Frag_Reticle_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, Tunnel) == 0x0002A8, "Member 'USPG9_Frag_Reticle_C::Tunnel' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, UnzoomedImage) == 0x0002B0, "Member 'USPG9_Frag_Reticle_C::UnzoomedImage' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, ZoomedImage) == 0x0002B8, "Member 'USPG9_Frag_Reticle_C::ZoomedImage' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, LastRot) == 0x0002C0, "Member 'USPG9_Frag_Reticle_C::LastRot' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, OffsetX) == 0x0002CC, "Member 'USPG9_Frag_Reticle_C::OffsetX' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, RotInterp) == 0x0002D0, "Member 'USPG9_Frag_Reticle_C::RotInterp' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, ParentWeapon) == 0x0002E0, "Member 'USPG9_Frag_Reticle_C::ParentWeapon' has a wrong offset!");
static_assert(offsetof(USPG9_Frag_Reticle_C, OffsetY) == 0x0002E8, "Member 'USPG9_Frag_Reticle_C::OffsetY' has a wrong offset!");

}

