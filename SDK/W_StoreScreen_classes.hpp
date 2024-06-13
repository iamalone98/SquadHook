#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_StoreScreen

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_StoreScreen.W_StoreScreen_C
// 0x00E0 (0x0390 - 0x02B0)
class UW_StoreScreen_C final : public USQUserWidget_StoreScreen
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02B0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       ShowPreview;                                       // 0x02B8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UOverlay*                               BGOverlay;                                         // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    BTTN_Emotes;                                       // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    BTTN_WeaponSkins;                                  // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BundleBackground;                                  // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    ButtonBack;                                        // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_227;                                         // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_288;                                         // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 MenuBackgroundCrosses;                             // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UNamedSlot*                             NamedSlot_BundlePreview;                           // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 PreviewOverlay;                                    // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 PreviewOverlay2;                                   // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 PreviewOverlayColourGradient;                      // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                SettingsItem_TickBox;                              // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 StoreBG;                                           // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 StoreBGOverlay;                                    // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             StoreScrollBox;                                    // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_0;                                  // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             LeaveStore;                                        // 0x0348(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class UODKBazaarBundle*>               TempBoughtBundles;                                 // 0x0358(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             OnGotoEquip;                                       // 0x0368(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UMainMenu_Button_C*                     StoreButton;                                       // 0x0378(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	bool                                          bIsActive;                                         // 0x0380(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3385[0x7];                                     // 0x0381(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_BundlePreview_C*                     W_BundlePreview;                                   // 0x0388(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void LeaveStore__DelegateSignature();
	void OnGotoEquip__DelegateSignature();
	void ExecuteUbergraph_W_StoreScreen(int32 EntryPoint);
	void AllCategories();
	void BndEvt__W_StoreScreen_BTTN_Emotes_K2Node_ComponentBoundEvent_7_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_StoreScreen_BTTN_WeaponSkins_K2Node_ComponentBoundEvent_5_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_StoreScreen_SettingsItem_TickBox_K2Node_ComponentBoundEvent_6_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__W_StoreScreen_ButtonBack_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void UpdateStoreAvailability(const struct FTitleData& TitleData);
	void OnTitleDataReady(const struct FTitleData& TitleData);
	void OnInitialized();
	void Construct();
	void OnScreenOpen();
	void LeaveScreen();
	void PreviewBundleScreen(const class UODKBazaarBundle* BazaarBundle);
	void GotoEquip();
	void DisplayPurchaseFanfare(class UODKBazaarBundle* NewlyBoughtBundle);
	void CheckForNextBundle(class UODKBazaarBundle* ClosedBundle);
	void OnPurchaseCompleted(const struct FODKBazaarPurchaseCompletedData& PurchaseCompletedData);
	void AddParallax(bool bInvert, float Percent, float StartX, float StartY, float* EndX, float* EndY);
	void CreateBazaarAnalyticEventData(class UODKBazaarItem* Bazaar_Item, TArray<struct FAnalyticKeyValue>* Event_Data);
	void UnselectNavButtons(class UWidget* Except);
	struct FEventReply OnEscPressed();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_StoreScreen_C">();
	}
	static class UW_StoreScreen_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_StoreScreen_C>();
	}
};
static_assert(alignof(UW_StoreScreen_C) == 0x000008, "Wrong alignment on UW_StoreScreen_C");
static_assert(sizeof(UW_StoreScreen_C) == 0x000390, "Wrong size on UW_StoreScreen_C");
static_assert(offsetof(UW_StoreScreen_C, UberGraphFrame) == 0x0002B0, "Member 'UW_StoreScreen_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, ShowPreview) == 0x0002B8, "Member 'UW_StoreScreen_C::ShowPreview' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, BGOverlay) == 0x0002C0, "Member 'UW_StoreScreen_C::BGOverlay' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, BTTN_Emotes) == 0x0002C8, "Member 'UW_StoreScreen_C::BTTN_Emotes' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, BTTN_WeaponSkins) == 0x0002D0, "Member 'UW_StoreScreen_C::BTTN_WeaponSkins' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, BundleBackground) == 0x0002D8, "Member 'UW_StoreScreen_C::BundleBackground' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, ButtonBack) == 0x0002E0, "Member 'UW_StoreScreen_C::ButtonBack' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, Image_227) == 0x0002E8, "Member 'UW_StoreScreen_C::Image_227' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, Image_288) == 0x0002F0, "Member 'UW_StoreScreen_C::Image_288' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, MenuBackgroundCrosses) == 0x0002F8, "Member 'UW_StoreScreen_C::MenuBackgroundCrosses' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, NamedSlot_BundlePreview) == 0x000300, "Member 'UW_StoreScreen_C::NamedSlot_BundlePreview' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, PreviewOverlay) == 0x000308, "Member 'UW_StoreScreen_C::PreviewOverlay' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, PreviewOverlay2) == 0x000310, "Member 'UW_StoreScreen_C::PreviewOverlay2' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, PreviewOverlayColourGradient) == 0x000318, "Member 'UW_StoreScreen_C::PreviewOverlayColourGradient' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, SettingsItem_TickBox) == 0x000320, "Member 'UW_StoreScreen_C::SettingsItem_TickBox' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, StoreBG) == 0x000328, "Member 'UW_StoreScreen_C::StoreBG' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, StoreBGOverlay) == 0x000330, "Member 'UW_StoreScreen_C::StoreBGOverlay' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, StoreScrollBox) == 0x000338, "Member 'UW_StoreScreen_C::StoreScrollBox' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, WidgetSwitcher_0) == 0x000340, "Member 'UW_StoreScreen_C::WidgetSwitcher_0' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, LeaveStore) == 0x000348, "Member 'UW_StoreScreen_C::LeaveStore' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, TempBoughtBundles) == 0x000358, "Member 'UW_StoreScreen_C::TempBoughtBundles' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, OnGotoEquip) == 0x000368, "Member 'UW_StoreScreen_C::OnGotoEquip' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, StoreButton) == 0x000378, "Member 'UW_StoreScreen_C::StoreButton' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, bIsActive) == 0x000380, "Member 'UW_StoreScreen_C::bIsActive' has a wrong offset!");
static_assert(offsetof(UW_StoreScreen_C, W_BundlePreview) == 0x000388, "Member 'UW_StoreScreen_C::W_BundlePreview' has a wrong offset!");

}
