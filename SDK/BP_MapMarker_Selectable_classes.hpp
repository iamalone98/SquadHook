#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_Selectable

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MapMarker_Selectable.BP_MapMarker_Selectable_C
// 0x0008 (0x0358 - 0x0350)
class UBP_MapMarker_Selectable_C : public USQMapMarkerBase
{
public:
	float                                         MarkerScale;                                       // 0x0350(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         FadeOpacity;                                       // 0x0354(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	struct FEventReply OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapMarker_Selectable_C">();
	}
	static class UBP_MapMarker_Selectable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MapMarker_Selectable_C>();
	}
};
static_assert(alignof(UBP_MapMarker_Selectable_C) == 0x000008, "Wrong alignment on UBP_MapMarker_Selectable_C");
static_assert(sizeof(UBP_MapMarker_Selectable_C) == 0x000358, "Wrong size on UBP_MapMarker_Selectable_C");
static_assert(offsetof(UBP_MapMarker_Selectable_C, MarkerScale) == 0x000350, "Member 'UBP_MapMarker_Selectable_C::MarkerScale' has a wrong offset!");
static_assert(offsetof(UBP_MapMarker_Selectable_C, FadeOpacity) == 0x000354, "Member 'UBP_MapMarker_Selectable_C::FadeOpacity' has a wrong offset!");

}
