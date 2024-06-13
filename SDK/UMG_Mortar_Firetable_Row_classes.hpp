#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Mortar_Firetable_Row

#include "Basic.hpp"

#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_Mortar_Firetable_Row.UMG_Mortar_Firetable_Row_C
// 0x0018 (0x0278 - 0x0260)
class UUMG_Mortar_Firetable_Row_C final : public UUserWidget
{
public:
	class UTextBlock*                             PitchTextBlock;                                    // 0x0260(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             RangeTextBlock;                                    // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TimeTextBox;                                       // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_Mortar_Firetable_Row_C">();
	}
	static class UUMG_Mortar_Firetable_Row_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_Mortar_Firetable_Row_C>();
	}
};
static_assert(alignof(UUMG_Mortar_Firetable_Row_C) == 0x000008, "Wrong alignment on UUMG_Mortar_Firetable_Row_C");
static_assert(sizeof(UUMG_Mortar_Firetable_Row_C) == 0x000278, "Wrong size on UUMG_Mortar_Firetable_Row_C");
static_assert(offsetof(UUMG_Mortar_Firetable_Row_C, PitchTextBlock) == 0x000260, "Member 'UUMG_Mortar_Firetable_Row_C::PitchTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Mortar_Firetable_Row_C, RangeTextBlock) == 0x000268, "Member 'UUMG_Mortar_Firetable_Row_C::RangeTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Mortar_Firetable_Row_C, TimeTextBox) == 0x000270, "Member 'UUMG_Mortar_Firetable_Row_C::TimeTextBox' has a wrong offset!");

}

