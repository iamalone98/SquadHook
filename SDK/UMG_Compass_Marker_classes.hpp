#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Compass_Marker

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_Compass_Marker.UMG_Compass_Marker_C
// 0x0058 (0x03C8 - 0x0370)
class UUMG_Compass_Marker_C final : public USQCompassMarker
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0370(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       In;                                                // 0x0378(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UTextBlock*                             BP_DistanceText;                                   // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BP_MeterText;                                      // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           BPMain_P;                                          // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BPMarker_IMG;                                      // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           CanvasPanel_856;                                   // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 LeadIcon;                                          // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_FT;                                             // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	ESQMapMarkerType                              Marker_Type;                                       // 0x03B8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39CD[0x7];                                     // 0x03B9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMG_Compass_C*                         ParentCompass;                                     // 0x03C0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_Compass_Marker(int32 EntryPoint);
	void Construct();
	void RefreshDisplayMode();
	void PreConstruct(bool IsDesignTime);
	void BPInit();
	void Set_Info();
	void ChangeDisplayMode(bool Param_bTopScreenView);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_Compass_Marker_C">();
	}
	static class UUMG_Compass_Marker_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_Compass_Marker_C>();
	}
};
static_assert(alignof(UUMG_Compass_Marker_C) == 0x000008, "Wrong alignment on UUMG_Compass_Marker_C");
static_assert(sizeof(UUMG_Compass_Marker_C) == 0x0003C8, "Wrong size on UUMG_Compass_Marker_C");
static_assert(offsetof(UUMG_Compass_Marker_C, UberGraphFrame) == 0x000370, "Member 'UUMG_Compass_Marker_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, In) == 0x000378, "Member 'UUMG_Compass_Marker_C::In' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, BP_DistanceText) == 0x000380, "Member 'UUMG_Compass_Marker_C::BP_DistanceText' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, BP_MeterText) == 0x000388, "Member 'UUMG_Compass_Marker_C::BP_MeterText' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, BPMain_P) == 0x000390, "Member 'UUMG_Compass_Marker_C::BPMain_P' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, BPMarker_IMG) == 0x000398, "Member 'UUMG_Compass_Marker_C::BPMarker_IMG' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, CanvasPanel_856) == 0x0003A0, "Member 'UUMG_Compass_Marker_C::CanvasPanel_856' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, LeadIcon) == 0x0003A8, "Member 'UUMG_Compass_Marker_C::LeadIcon' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, TB_FT) == 0x0003B0, "Member 'UUMG_Compass_Marker_C::TB_FT' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, Marker_Type) == 0x0003B8, "Member 'UUMG_Compass_Marker_C::Marker_Type' has a wrong offset!");
static_assert(offsetof(UUMG_Compass_Marker_C, ParentCompass) == 0x0003C0, "Member 'UUMG_Compass_Marker_C::ParentCompass' has a wrong offset!");

}
