#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Mortar_Firetable

#include "Basic.hpp"

#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_Mortar_Firetable.UMG_Mortar_Firetable_C
// 0x0008 (0x0268 - 0x0260)
class UUMG_Mortar_Firetable_C final : public UUserWidget
{
public:
	class UVerticalBox*                           RangePanel;                                        // 0x0260(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_Mortar_Firetable_C">();
	}
	static class UUMG_Mortar_Firetable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_Mortar_Firetable_C>();
	}
};
static_assert(alignof(UUMG_Mortar_Firetable_C) == 0x000008, "Wrong alignment on UUMG_Mortar_Firetable_C");
static_assert(sizeof(UUMG_Mortar_Firetable_C) == 0x000268, "Wrong size on UUMG_Mortar_Firetable_C");
static_assert(offsetof(UUMG_Mortar_Firetable_C, RangePanel) == 0x000260, "Member 'UUMG_Mortar_Firetable_C::RangePanel' has a wrong offset!");

}

