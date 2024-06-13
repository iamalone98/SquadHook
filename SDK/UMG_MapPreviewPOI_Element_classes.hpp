#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_MapPreviewPOI_Element

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_MapPreviewPOI_Element.UMG_MapPreviewPOI_Element_C
// 0x0070 (0x02D0 - 0x0260)
class UUMG_MapPreviewPOI_Element_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Hover;                                             // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 DisplayTexture;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_84;                                          // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                MainButon;                                         // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               MainSB;                                            // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        MainSwitcher;                                      // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             NumberText;                                        // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   POINameText;                                       // 0x02A8(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             PoiHovered;                                        // 0x02C0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void PoiHovered__DelegateSignature(class UUMG_MapPreviewPOI_Element_C* POI, bool Hovered);
	void ExecuteUbergraph_UMG_MapPreviewPOI_Element(int32 EntryPoint);
	void BndEvt__UMG_MapPreviewPOI_Element_MainButon_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__UMG_MapPreviewPOI_Element_MainButon_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature();
	void FillTexture(class UTexture2D* Texture, const struct FLinearColor& Color, int32 DisplayIndex, const class FText& DisplayName);
	void SetPosition(const struct FVector2D& Pos);
	void ChangeDisplayMode(int32 NewMode, float NewSize);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_MapPreviewPOI_Element_C">();
	}
	static class UUMG_MapPreviewPOI_Element_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_MapPreviewPOI_Element_C>();
	}
};
static_assert(alignof(UUMG_MapPreviewPOI_Element_C) == 0x000008, "Wrong alignment on UUMG_MapPreviewPOI_Element_C");
static_assert(sizeof(UUMG_MapPreviewPOI_Element_C) == 0x0002D0, "Wrong size on UUMG_MapPreviewPOI_Element_C");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, UberGraphFrame) == 0x000260, "Member 'UUMG_MapPreviewPOI_Element_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, Hover) == 0x000268, "Member 'UUMG_MapPreviewPOI_Element_C::Hover' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, DisplayTexture) == 0x000270, "Member 'UUMG_MapPreviewPOI_Element_C::DisplayTexture' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, Image) == 0x000278, "Member 'UUMG_MapPreviewPOI_Element_C::Image' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, Image_84) == 0x000280, "Member 'UUMG_MapPreviewPOI_Element_C::Image_84' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, MainButon) == 0x000288, "Member 'UUMG_MapPreviewPOI_Element_C::MainButon' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, MainSB) == 0x000290, "Member 'UUMG_MapPreviewPOI_Element_C::MainSB' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, MainSwitcher) == 0x000298, "Member 'UUMG_MapPreviewPOI_Element_C::MainSwitcher' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, NumberText) == 0x0002A0, "Member 'UUMG_MapPreviewPOI_Element_C::NumberText' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, POINameText) == 0x0002A8, "Member 'UUMG_MapPreviewPOI_Element_C::POINameText' has a wrong offset!");
static_assert(offsetof(UUMG_MapPreviewPOI_Element_C, PoiHovered) == 0x0002C0, "Member 'UUMG_MapPreviewPOI_Element_C::PoiHovered' has a wrong offset!");

}

