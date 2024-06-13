#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CustomizeScreen

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"
#include "ODKBazaar_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_CustomizeScreen.W_CustomizeScreen_C
// 0x01E0 (0x04C0 - 0x02E0)
class UW_CustomizeScreen_C final : public USQCustomizationScreen
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       HideUIRot;                                         // 0x02E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       ToggleFullscreen;                                  // 0x02F0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       OnEquipped;                                        // 0x02F8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UOverlay*                               BGOverlay;                                         // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_SkinDesc;                                   // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_WeaponInfo;                                 // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    BTTN_Emotes;                                       // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    BTTN_WeaponSkins;                                  // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    Button_Equip;                                      // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    Button_FullScreen;                                 // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    ButtonBack_1;                                      // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CustomizeBG;                                       // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CustomizeBGOverlay;                                // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CustomizeBGOverlay_1;                              // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DarkenPanel;                                       // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             EmoteDescription;                                  // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             EmoteName;                                         // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                EquippedNotify;                                    // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUniformGridPanel*                      Grid_FactionIcons;                                 // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUniformGridPanel*                      Grid_RoleIcons;                                    // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_BiomeLabels;                         // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_WeaponInfo;                          // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_227;                                         // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             InputHintTextBox;                                  // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         ItemCategoryBar;                                   // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 LargeFlag;                                         // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 MenuBackgroundCrosses;                             // 0x03B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         Overlay_Footer;                                    // 0x03C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_TeamDisplay;                               // 0x03C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 PreviewOverlayColourGradient;                      // 0x03D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        PreviewSwitcher;                                   // 0x03D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_TeamImage;                                // 0x03E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 StoreBGOverlay;                                    // 0x03E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             StoreScrollBox;                                    // 0x03F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_EmoteTag;                                       // 0x03F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_EquipNotify;                                    // 0x0400(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_WeaponName;                                     // 0x0408(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_YouDontOwnSkins;                                // 0x0410(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TeamImage;                                         // 0x0418(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VerticalBox_Inventory;                             // 0x0420(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_SoldierPreview_C*                    W_SoldierPreview;                                  // 0x0428(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_WeaponPreview_C*                     W_WeaponPreview;                                   // 0x0430(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_OwnedSkinsText;                     // 0x0438(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USQEmotesDataTable*                     DLCTable;                                          // 0x0440(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQEmotesData*                          LastClicked;                                       // 0x0448(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMainMenuScreen_C*                      MainMenu;                                          // 0x0450(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          EmoteWheelVisible;                                 // 0x0458(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_24BA[0x7];                                     // 0x0459(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnCloseCustomize;                                  // 0x0460(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UBaseRadialMenu_C*                      EmoteWheel;                                        // 0x0470(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class USQItemSkinCollection*>          WeaponSkinsArray;                                  // 0x0478(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	class FName                                   CurrentlySelectedFaction;                          // 0x0488(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UTexture2D*>                     CurrentRoleIcons;                                  // 0x0490(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          bFullScreen;                                       // 0x04A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_24BB[0x3];                                     // 0x04A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   Weapon_Skin_Name;                                  // 0x04A4(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_24BC[0x4];                                     // 0x04AC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               MID_Flag;                                          // 0x04B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bHideUI;                                           // 0x04B8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void OnCloseCustomize__DelegateSignature();
	void ExecuteUbergraph_W_CustomizeScreen(int32 EntryPoint);
	void BndEvt__W_CustomizeScreen_W_WeaponPreview_K2Node_ComponentBoundEvent_8_OnMouseMoved__DelegateSignature();
	void BndEvt__W_CustomizeScreen_W_WeaponPreview_K2Node_ComponentBoundEvent_4_OnMouseButtonReleased__DelegateSignature();
	void ManualEquip();
	void BndEvt__W_CustomizeScreen_Button_Equip_K2Node_ComponentBoundEvent_6_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void Construct();
	void BndEvt__W_CustomizeScreen_ButtonBack_1_K2Node_ComponentBoundEvent_5_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_CustomizeScreen_Button_FullScreen_K2Node_ComponentBoundEvent_3_OnButtonClickedEvent__DelegateSignature();
	void OnEmoteSelected(class USQEmotesData* EmoteData);
	void BndEvt__W_CustomizeScreen_BTTN_Emotes_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_CustomizeScreen_BTTN_WeaponSkins_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void OnPurchaseCompleted(const struct FODKBazaarPurchaseCompletedData& PurchaseCompletedData);
	void UpdateHintText();
	void OnScreenOpen();
	void OnScreenClosed();
	void PopulateEmoteGrid();
	void CreateAndDisplayEmoteWheel();
	void RemoveEmoteWheel();
	void UpdateEquippedEmotesItems();
	void CheckFactionRestriction(class USQEmotesData* EmoteData);
	void AddParallax(bool bInvert, float Percent, float StartX, float StartY, float* EndX, float* EndY);
	void OnRadialClicked(int32 OptionIndex, class UBaseRadialMenu_C* Context);
	void OnItemHovered(class USQEmotesData* EmoteData);
	void PopulateSkinGrid();
	void OnEmoteHovered(class USQEmotesData* EmoteData);
	void OnWeaponSkinSelected(const class FName& SkinName);
	void OnWeaponSkinHovered(class USQItemSkinCollection* SkinData);
	void OnFactionSelected(class FName FactionName);
	void OnFactionHovered(class FName FactionName);
	void ToggleFullScreenPreview();
	ESlateVisibility Get_Button_FullScreen_Visibility_0();
	struct FEventReply OnEscPressed();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_CustomizeScreen_C">();
	}
	static class UW_CustomizeScreen_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_CustomizeScreen_C>();
	}
};
static_assert(alignof(UW_CustomizeScreen_C) == 0x000008, "Wrong alignment on UW_CustomizeScreen_C");
static_assert(sizeof(UW_CustomizeScreen_C) == 0x0004C0, "Wrong size on UW_CustomizeScreen_C");
static_assert(offsetof(UW_CustomizeScreen_C, UberGraphFrame) == 0x0002E0, "Member 'UW_CustomizeScreen_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, HideUIRot) == 0x0002E8, "Member 'UW_CustomizeScreen_C::HideUIRot' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, ToggleFullscreen) == 0x0002F0, "Member 'UW_CustomizeScreen_C::ToggleFullscreen' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, OnEquipped) == 0x0002F8, "Member 'UW_CustomizeScreen_C::OnEquipped' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, BGOverlay) == 0x000300, "Member 'UW_CustomizeScreen_C::BGOverlay' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Border_SkinDesc) == 0x000308, "Member 'UW_CustomizeScreen_C::Border_SkinDesc' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Border_WeaponInfo) == 0x000310, "Member 'UW_CustomizeScreen_C::Border_WeaponInfo' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, BTTN_Emotes) == 0x000318, "Member 'UW_CustomizeScreen_C::BTTN_Emotes' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, BTTN_WeaponSkins) == 0x000320, "Member 'UW_CustomizeScreen_C::BTTN_WeaponSkins' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Button_Equip) == 0x000328, "Member 'UW_CustomizeScreen_C::Button_Equip' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Button_FullScreen) == 0x000330, "Member 'UW_CustomizeScreen_C::Button_FullScreen' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, ButtonBack_1) == 0x000338, "Member 'UW_CustomizeScreen_C::ButtonBack_1' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, CustomizeBG) == 0x000340, "Member 'UW_CustomizeScreen_C::CustomizeBG' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, CustomizeBGOverlay) == 0x000348, "Member 'UW_CustomizeScreen_C::CustomizeBGOverlay' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, CustomizeBGOverlay_1) == 0x000350, "Member 'UW_CustomizeScreen_C::CustomizeBGOverlay_1' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, DarkenPanel) == 0x000358, "Member 'UW_CustomizeScreen_C::DarkenPanel' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, EmoteDescription) == 0x000360, "Member 'UW_CustomizeScreen_C::EmoteDescription' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, EmoteName) == 0x000368, "Member 'UW_CustomizeScreen_C::EmoteName' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, EquippedNotify) == 0x000370, "Member 'UW_CustomizeScreen_C::EquippedNotify' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Grid_FactionIcons) == 0x000378, "Member 'UW_CustomizeScreen_C::Grid_FactionIcons' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Grid_RoleIcons) == 0x000380, "Member 'UW_CustomizeScreen_C::Grid_RoleIcons' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, HorizontalBox_BiomeLabels) == 0x000388, "Member 'UW_CustomizeScreen_C::HorizontalBox_BiomeLabels' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, HorizontalBox_WeaponInfo) == 0x000390, "Member 'UW_CustomizeScreen_C::HorizontalBox_WeaponInfo' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Image_227) == 0x000398, "Member 'UW_CustomizeScreen_C::Image_227' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, InputHintTextBox) == 0x0003A0, "Member 'UW_CustomizeScreen_C::InputHintTextBox' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, ItemCategoryBar) == 0x0003A8, "Member 'UW_CustomizeScreen_C::ItemCategoryBar' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, LargeFlag) == 0x0003B0, "Member 'UW_CustomizeScreen_C::LargeFlag' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, MenuBackgroundCrosses) == 0x0003B8, "Member 'UW_CustomizeScreen_C::MenuBackgroundCrosses' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Overlay_Footer) == 0x0003C0, "Member 'UW_CustomizeScreen_C::Overlay_Footer' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Overlay_TeamDisplay) == 0x0003C8, "Member 'UW_CustomizeScreen_C::Overlay_TeamDisplay' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, PreviewOverlayColourGradient) == 0x0003D0, "Member 'UW_CustomizeScreen_C::PreviewOverlayColourGradient' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, PreviewSwitcher) == 0x0003D8, "Member 'UW_CustomizeScreen_C::PreviewSwitcher' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, ScaleBox_TeamImage) == 0x0003E0, "Member 'UW_CustomizeScreen_C::ScaleBox_TeamImage' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, StoreBGOverlay) == 0x0003E8, "Member 'UW_CustomizeScreen_C::StoreBGOverlay' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, StoreScrollBox) == 0x0003F0, "Member 'UW_CustomizeScreen_C::StoreScrollBox' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, TB_EmoteTag) == 0x0003F8, "Member 'UW_CustomizeScreen_C::TB_EmoteTag' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, TB_EquipNotify) == 0x000400, "Member 'UW_CustomizeScreen_C::TB_EquipNotify' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, TB_WeaponName) == 0x000408, "Member 'UW_CustomizeScreen_C::TB_WeaponName' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, TB_YouDontOwnSkins) == 0x000410, "Member 'UW_CustomizeScreen_C::TB_YouDontOwnSkins' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, TeamImage) == 0x000418, "Member 'UW_CustomizeScreen_C::TeamImage' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, VerticalBox_Inventory) == 0x000420, "Member 'UW_CustomizeScreen_C::VerticalBox_Inventory' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, W_SoldierPreview) == 0x000428, "Member 'UW_CustomizeScreen_C::W_SoldierPreview' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, W_WeaponPreview) == 0x000430, "Member 'UW_CustomizeScreen_C::W_WeaponPreview' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, WidgetSwitcher_OwnedSkinsText) == 0x000438, "Member 'UW_CustomizeScreen_C::WidgetSwitcher_OwnedSkinsText' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, DLCTable) == 0x000440, "Member 'UW_CustomizeScreen_C::DLCTable' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, LastClicked) == 0x000448, "Member 'UW_CustomizeScreen_C::LastClicked' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, MainMenu) == 0x000450, "Member 'UW_CustomizeScreen_C::MainMenu' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, EmoteWheelVisible) == 0x000458, "Member 'UW_CustomizeScreen_C::EmoteWheelVisible' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, OnCloseCustomize) == 0x000460, "Member 'UW_CustomizeScreen_C::OnCloseCustomize' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, EmoteWheel) == 0x000470, "Member 'UW_CustomizeScreen_C::EmoteWheel' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, WeaponSkinsArray) == 0x000478, "Member 'UW_CustomizeScreen_C::WeaponSkinsArray' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, CurrentlySelectedFaction) == 0x000488, "Member 'UW_CustomizeScreen_C::CurrentlySelectedFaction' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, CurrentRoleIcons) == 0x000490, "Member 'UW_CustomizeScreen_C::CurrentRoleIcons' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, bFullScreen) == 0x0004A0, "Member 'UW_CustomizeScreen_C::bFullScreen' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, Weapon_Skin_Name) == 0x0004A4, "Member 'UW_CustomizeScreen_C::Weapon_Skin_Name' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, MID_Flag) == 0x0004B0, "Member 'UW_CustomizeScreen_C::MID_Flag' has a wrong offset!");
static_assert(offsetof(UW_CustomizeScreen_C, bHideUI) == 0x0004B8, "Member 'UW_CustomizeScreen_C::bHideUI' has a wrong offset!");

}

