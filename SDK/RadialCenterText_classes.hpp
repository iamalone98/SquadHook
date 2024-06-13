#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialCenterText

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass RadialCenterText.RadialCenterText_C
// 0x00B0 (0x03E0 - 0x0330)
class URadialCenterText_C final : public USQRadialButton
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0330(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Background;                                        // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BottomDivider;                                     // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPText;                                            // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           CanvasPanel_0;                                     // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TopDivider;                                        // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   Text;                                              // 0x0360(0x0018)(Edit, BlueprintVisible)
	class FText                                   CachedRearmCostText;                               // 0x0378(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class UBaseRadialMenu_C*                      OwnerRadialMenu;                                   // 0x0390(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  RelatedActionModel;                                // 0x0398(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           UnavailableHammer;                                 // 0x03A0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           UnavailableHexagon;                                // 0x03B0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           AvailableHexagon;                                  // 0x03C0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           AvailableHammer;                                   // 0x03D0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_RadialCenterText(int32 EntryPoint);
	void OnHoverBegin();
	class FText GetCenterText();
	void GetWidgetText(class USQRadialButton* Widget, class FText* DisplayText);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"RadialCenterText_C">();
	}
	static class URadialCenterText_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<URadialCenterText_C>();
	}
};
static_assert(alignof(URadialCenterText_C) == 0x000008, "Wrong alignment on URadialCenterText_C");
static_assert(sizeof(URadialCenterText_C) == 0x0003E0, "Wrong size on URadialCenterText_C");
static_assert(offsetof(URadialCenterText_C, UberGraphFrame) == 0x000330, "Member 'URadialCenterText_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, Background) == 0x000338, "Member 'URadialCenterText_C::Background' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, BottomDivider) == 0x000340, "Member 'URadialCenterText_C::BottomDivider' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, BPText) == 0x000348, "Member 'URadialCenterText_C::BPText' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, CanvasPanel_0) == 0x000350, "Member 'URadialCenterText_C::CanvasPanel_0' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, TopDivider) == 0x000358, "Member 'URadialCenterText_C::TopDivider' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, Text) == 0x000360, "Member 'URadialCenterText_C::Text' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, CachedRearmCostText) == 0x000378, "Member 'URadialCenterText_C::CachedRearmCostText' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, OwnerRadialMenu) == 0x000390, "Member 'URadialCenterText_C::OwnerRadialMenu' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, RelatedActionModel) == 0x000398, "Member 'URadialCenterText_C::RelatedActionModel' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, UnavailableHammer) == 0x0003A0, "Member 'URadialCenterText_C::UnavailableHammer' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, UnavailableHexagon) == 0x0003B0, "Member 'URadialCenterText_C::UnavailableHexagon' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, AvailableHexagon) == 0x0003C0, "Member 'URadialCenterText_C::AvailableHexagon' has a wrong offset!");
static_assert(offsetof(URadialCenterText_C, AvailableHammer) == 0x0003D0, "Member 'URadialCenterText_C::AvailableHammer' has a wrong offset!");

}
