#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_RepairStation

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MarkerWidget_RepairStation.BP_MarkerWidget_RepairStation_C
// 0x0028 (0x02A8 - 0x0280)
class UBP_MarkerWidget_RepairStation_C final : public USQMapIconWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0280(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 MarkerImage;                                       // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_0;                                         // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         StateUpdateTime;                                   // 0x0298(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4F7A[0x4];                                     // 0x029C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQMapIconComponent*                    SQ_Map_Icon;                                       // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MarkerWidget_RepairStation(int32 EntryPoint);
	void Find_SQ_Map_Icon();
	void Construct();
	void UpdateMarkerImageBrush();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MarkerWidget_RepairStation_C">();
	}
	static class UBP_MarkerWidget_RepairStation_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MarkerWidget_RepairStation_C>();
	}
};
static_assert(alignof(UBP_MarkerWidget_RepairStation_C) == 0x000008, "Wrong alignment on UBP_MarkerWidget_RepairStation_C");
static_assert(sizeof(UBP_MarkerWidget_RepairStation_C) == 0x0002A8, "Wrong size on UBP_MarkerWidget_RepairStation_C");
static_assert(offsetof(UBP_MarkerWidget_RepairStation_C, UberGraphFrame) == 0x000280, "Member 'UBP_MarkerWidget_RepairStation_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_RepairStation_C, MarkerImage) == 0x000288, "Member 'UBP_MarkerWidget_RepairStation_C::MarkerImage' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_RepairStation_C, Overlay_0) == 0x000290, "Member 'UBP_MarkerWidget_RepairStation_C::Overlay_0' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_RepairStation_C, StateUpdateTime) == 0x000298, "Member 'UBP_MarkerWidget_RepairStation_C::StateUpdateTime' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_RepairStation_C, SQ_Map_Icon) == 0x0002A0, "Member 'UBP_MarkerWidget_RepairStation_C::SQ_Map_Icon' has a wrong offset!");

}
