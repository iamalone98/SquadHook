#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_BundlePreview

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"
#include "ODKBazaar_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_BundlePreview.W_BundlePreview_C
// 0x0130 (0x0410 - 0x02E0)
class UW_BundlePreview_C final : public USQCustomizationScreen
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       HideUIRotation;                                    // 0x02E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       ToggleFullscreen;                                  // 0x02F0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Border_EmoteDesc;                                  // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_SkinDesc;                                   // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_WeaponInfo;                                 // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    Button_FullScreen;                                 // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    ButtonPurchase;                                    // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                FrameBorder;                                       // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUniformGridPanel*                      Grid_FactionIcons;                                 // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUniformGridPanel*                      Grid_RoleIcons;                                    // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_BiomeLabels;                         // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_WeaponInfo;                          // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             MTB_EmoteDescription;                              // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             MTB_SkinDescription;                               // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        OwnedSwitcher;                                     // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        PreviewSwitcher;                                   // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_BundleSubTitle;                                 // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ClickToPreview;                                 // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_EmoteTag;                                       // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_EmoteTitle;                                     // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_SkinTitle;                                      // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Title;                                          // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_WeaponName;                                     // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_WeaponSkinTag;                                  // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_SoldierPreview_C*                    W_SoldierPreview;                                  // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_WeaponPreview_C*                     W_WeaponPreview;                                   // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UODKBazaarBundle*                       Bundle;                                            // 0x03B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         EmotesGridSize;                                    // 0x03C0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3319[0x4];                                     // 0x03C4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnClosed;                                          // 0x03C8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UW_StoreScreen_C*                       StoreScreen;                                       // 0x03D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class USQItemSkinCollection*>          WeaponSkinsArray;                                  // 0x03E0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class UTexture2D*>                     CurrentRoleIcons;                                  // 0x03F0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          bFullScreen;                                       // 0x0400(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_331A[0x3];                                     // 0x0401(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         WeaponSkinGridSize;                                // 0x0404(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bHideUI;                                           // 0x0408(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void OnClosed__DelegateSignature();
	void ExecuteUbergraph_W_BundlePreview(int32 EntryPoint);
	void BndEvt__W_BundlePreview_W_WeaponPreview_K2Node_ComponentBoundEvent_4_OnMouseMoved__DelegateSignature();
	void BndEvt__W_BundlePreview_W_WeaponPreview_K2Node_ComponentBoundEvent_3_OnMouseButtonReleased__DelegateSignature();
	void BndEvt__W_BundlePreview_Button_FullScreen_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature();
	void OnScreenOpen();
	void OnScreenClosed();
	void BndEvt__W_BundlePreview_ButtonBack_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void CheckOwned();
	void PopulateStoreGrid();
	void CheckFactionRestrictions(class USQEmotesData* EmoteData);
	void OnItemHovered(class USQEmotesData* EmoteData);
	void OnEmoteHovered(class USQEmotesData* EmoteData);
	void OnWeaponSkinHovered(class USQItemSkinCollection* SkinData);
	void SelectFirstEmoteInBundle();
	void SelectFirstSkinInBundle();
	void ToggleFullScreenPreview();
	ESlateVisibility Get_Button_FullScreen_Visibility_0();
	void OnWeaponSkinSelected(const class FName& SkinName);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_BundlePreview_C">();
	}
	static class UW_BundlePreview_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_BundlePreview_C>();
	}
};
static_assert(alignof(UW_BundlePreview_C) == 0x000008, "Wrong alignment on UW_BundlePreview_C");
static_assert(sizeof(UW_BundlePreview_C) == 0x000410, "Wrong size on UW_BundlePreview_C");
static_assert(offsetof(UW_BundlePreview_C, UberGraphFrame) == 0x0002E0, "Member 'UW_BundlePreview_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, HideUIRotation) == 0x0002E8, "Member 'UW_BundlePreview_C::HideUIRotation' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, ToggleFullscreen) == 0x0002F0, "Member 'UW_BundlePreview_C::ToggleFullscreen' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Border_EmoteDesc) == 0x0002F8, "Member 'UW_BundlePreview_C::Border_EmoteDesc' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Border_SkinDesc) == 0x000300, "Member 'UW_BundlePreview_C::Border_SkinDesc' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Border_WeaponInfo) == 0x000308, "Member 'UW_BundlePreview_C::Border_WeaponInfo' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Button_FullScreen) == 0x000310, "Member 'UW_BundlePreview_C::Button_FullScreen' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, ButtonPurchase) == 0x000318, "Member 'UW_BundlePreview_C::ButtonPurchase' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, FrameBorder) == 0x000320, "Member 'UW_BundlePreview_C::FrameBorder' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Grid_FactionIcons) == 0x000328, "Member 'UW_BundlePreview_C::Grid_FactionIcons' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Grid_RoleIcons) == 0x000330, "Member 'UW_BundlePreview_C::Grid_RoleIcons' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, HorizontalBox_BiomeLabels) == 0x000338, "Member 'UW_BundlePreview_C::HorizontalBox_BiomeLabels' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, HorizontalBox_WeaponInfo) == 0x000340, "Member 'UW_BundlePreview_C::HorizontalBox_WeaponInfo' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, MTB_EmoteDescription) == 0x000348, "Member 'UW_BundlePreview_C::MTB_EmoteDescription' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, MTB_SkinDescription) == 0x000350, "Member 'UW_BundlePreview_C::MTB_SkinDescription' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, OwnedSwitcher) == 0x000358, "Member 'UW_BundlePreview_C::OwnedSwitcher' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, PreviewSwitcher) == 0x000360, "Member 'UW_BundlePreview_C::PreviewSwitcher' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_BundleSubTitle) == 0x000368, "Member 'UW_BundlePreview_C::TB_BundleSubTitle' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_ClickToPreview) == 0x000370, "Member 'UW_BundlePreview_C::TB_ClickToPreview' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_EmoteTag) == 0x000378, "Member 'UW_BundlePreview_C::TB_EmoteTag' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_EmoteTitle) == 0x000380, "Member 'UW_BundlePreview_C::TB_EmoteTitle' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_SkinTitle) == 0x000388, "Member 'UW_BundlePreview_C::TB_SkinTitle' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_Title) == 0x000390, "Member 'UW_BundlePreview_C::TB_Title' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_WeaponName) == 0x000398, "Member 'UW_BundlePreview_C::TB_WeaponName' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, TB_WeaponSkinTag) == 0x0003A0, "Member 'UW_BundlePreview_C::TB_WeaponSkinTag' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, W_SoldierPreview) == 0x0003A8, "Member 'UW_BundlePreview_C::W_SoldierPreview' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, W_WeaponPreview) == 0x0003B0, "Member 'UW_BundlePreview_C::W_WeaponPreview' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, Bundle) == 0x0003B8, "Member 'UW_BundlePreview_C::Bundle' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, EmotesGridSize) == 0x0003C0, "Member 'UW_BundlePreview_C::EmotesGridSize' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, OnClosed) == 0x0003C8, "Member 'UW_BundlePreview_C::OnClosed' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, StoreScreen) == 0x0003D8, "Member 'UW_BundlePreview_C::StoreScreen' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, WeaponSkinsArray) == 0x0003E0, "Member 'UW_BundlePreview_C::WeaponSkinsArray' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, CurrentRoleIcons) == 0x0003F0, "Member 'UW_BundlePreview_C::CurrentRoleIcons' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, bFullScreen) == 0x000400, "Member 'UW_BundlePreview_C::bFullScreen' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, WeaponSkinGridSize) == 0x000404, "Member 'UW_BundlePreview_C::WeaponSkinGridSize' has a wrong offset!");
static_assert(offsetof(UW_BundlePreview_C, bHideUI) == 0x000408, "Member 'UW_BundlePreview_C::bHideUI' has a wrong offset!");

}

