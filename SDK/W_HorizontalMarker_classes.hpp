#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_HorizontalMarker

#include "Basic.hpp"

#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_HorizontalMarker.W_HorizontalMarker_C
// 0x0018 (0x0278 - 0x0260)
class UW_HorizontalMarker_C final : public UUserWidget
{
public:
	class UImage*                                 LeftBorder;                                        // 0x0260(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RightBorder;                                       // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Text;                                              // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_HorizontalMarker_C">();
	}
	static class UW_HorizontalMarker_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_HorizontalMarker_C>();
	}
};
static_assert(alignof(UW_HorizontalMarker_C) == 0x000008, "Wrong alignment on UW_HorizontalMarker_C");
static_assert(sizeof(UW_HorizontalMarker_C) == 0x000278, "Wrong size on UW_HorizontalMarker_C");
static_assert(offsetof(UW_HorizontalMarker_C, LeftBorder) == 0x000260, "Member 'UW_HorizontalMarker_C::LeftBorder' has a wrong offset!");
static_assert(offsetof(UW_HorizontalMarker_C, RightBorder) == 0x000268, "Member 'UW_HorizontalMarker_C::RightBorder' has a wrong offset!");
static_assert(offsetof(UW_HorizontalMarker_C, Text) == 0x000270, "Member 'UW_HorizontalMarker_C::Text' has a wrong offset!");

}

