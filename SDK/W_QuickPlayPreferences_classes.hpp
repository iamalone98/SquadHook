#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_QuickPlayPreferences

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_QuickPlayPreferences.W_QuickPlayPreferences_C
// 0x0200 (0x0460 - 0x0260)
class UW_QuickPlayPreferences_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_Filters;                                    // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Filters_GM;                                 // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BottomBorder;                                      // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    ButtonResetFilters;                                // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           GameModeFilters;                                   // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_148;                                         // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 PingSlider;                                        // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           ServerFilters;                                     // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_ElapsedTime;                              // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_Experience;                               // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_MapRot;                                   // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_MinPlayers;                               // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_Playstyle;                                // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                Settings_QPType;                                   // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                SettingsComboboxItem;                              // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Main;                                           // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Main_1;                                         // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TopBorder;                                         // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USaveData_UI_C*                         Save_Data;                                         // 0x0300(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Option_Changed;                                    // 0x0308(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class USettingsItem_TickBox_C*>        TagFilters;                                        // 0x0318(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	TMap<class FString, class FName>              LanguageMap;                                       // 0x0328(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             RequestClose;                                      // 0x0378(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class FText                                   AnyFilterText;                                     // 0x0388(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	TMap<class FName, class FText>                GameModeDisplay;                                   // 0x03A0(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<int32>                                 ElapsedTimeRange;                                  // 0x03F0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FName>                           PlaystyleTags;                                     // 0x0400(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FName>                           ExperienceTags;                                    // 0x0410(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FName>                           MapRotationTags;                                   // 0x0420(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FText>                           QPTypeTags;                                        // 0x0430(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FString>                         GameModeOptions;                                   // 0x0440(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FName>                           GameModeTags;                                      // 0x0450(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void Option_Changed__DelegateSignature();
	void RequestClose__DelegateSignature();
	void ExecuteUbergraph_W_QuickPlayPreferences(int32 EntryPoint);
	void BndEvt__W_QuickPlayPreferences_Settings_MapRot_K2Node_ComponentBoundEvent_8_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_Settings_Experience_K2Node_ComponentBoundEvent_7_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_Settings_Playstyle_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_Settings_QPType_K2Node_ComponentBoundEvent_5_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_Settings_ElapsedTime_K2Node_ComponentBoundEvent_4_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_Settings_MinPlayers_K2Node_ComponentBoundEvent_3_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_SettingsComboboxItem_K2Node_ComponentBoundEvent_2_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__W_QuickPlayPreferences_PingSlider_K2Node_ComponentBoundEvent_0_OnCaptureEnd__DelegateSignature(float Value);
	void BndEvt__W_QuickPlayPreferences_ButtonResetFilters_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void Construct();
	class UWidget* FavouriteTooltip();
	void FillTagFilters();
	void UpdateFromUserSettings(class USQQuickPlaySearch* QPObject);
	void UpdateSelectedFilters(class USQQuickPlaySearch* QPObject, bool* ChangeDetected);
	void ResetFilters();
	void UpdateResetDefaultButton();
	void GameModeSelectionChanged(bool bSelected, class USettingsItem_TickBox_C* Button);

	void GetSelectedTags(TArray<class FName>* Tags) const;
	void GetSelectedPing(int32* Ping) const;
	void IsOnDefaultValues(bool* Default) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_QuickPlayPreferences_C">();
	}
	static class UW_QuickPlayPreferences_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_QuickPlayPreferences_C>();
	}
};
static_assert(alignof(UW_QuickPlayPreferences_C) == 0x000008, "Wrong alignment on UW_QuickPlayPreferences_C");
static_assert(sizeof(UW_QuickPlayPreferences_C) == 0x000460, "Wrong size on UW_QuickPlayPreferences_C");
static_assert(offsetof(UW_QuickPlayPreferences_C, UberGraphFrame) == 0x000260, "Member 'UW_QuickPlayPreferences_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Border_Filters) == 0x000268, "Member 'UW_QuickPlayPreferences_C::Border_Filters' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Border_Filters_GM) == 0x000270, "Member 'UW_QuickPlayPreferences_C::Border_Filters_GM' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, BottomBorder) == 0x000278, "Member 'UW_QuickPlayPreferences_C::BottomBorder' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, ButtonResetFilters) == 0x000280, "Member 'UW_QuickPlayPreferences_C::ButtonResetFilters' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, GameModeFilters) == 0x000288, "Member 'UW_QuickPlayPreferences_C::GameModeFilters' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Image) == 0x000290, "Member 'UW_QuickPlayPreferences_C::Image' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Image_148) == 0x000298, "Member 'UW_QuickPlayPreferences_C::Image_148' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, PingSlider) == 0x0002A0, "Member 'UW_QuickPlayPreferences_C::PingSlider' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, ServerFilters) == 0x0002A8, "Member 'UW_QuickPlayPreferences_C::ServerFilters' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_ElapsedTime) == 0x0002B0, "Member 'UW_QuickPlayPreferences_C::Settings_ElapsedTime' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_Experience) == 0x0002B8, "Member 'UW_QuickPlayPreferences_C::Settings_Experience' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_MapRot) == 0x0002C0, "Member 'UW_QuickPlayPreferences_C::Settings_MapRot' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_MinPlayers) == 0x0002C8, "Member 'UW_QuickPlayPreferences_C::Settings_MinPlayers' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_Playstyle) == 0x0002D0, "Member 'UW_QuickPlayPreferences_C::Settings_Playstyle' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Settings_QPType) == 0x0002D8, "Member 'UW_QuickPlayPreferences_C::Settings_QPType' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, SettingsComboboxItem) == 0x0002E0, "Member 'UW_QuickPlayPreferences_C::SettingsComboboxItem' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, TB_Main) == 0x0002E8, "Member 'UW_QuickPlayPreferences_C::TB_Main' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, TB_Main_1) == 0x0002F0, "Member 'UW_QuickPlayPreferences_C::TB_Main_1' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, TopBorder) == 0x0002F8, "Member 'UW_QuickPlayPreferences_C::TopBorder' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Save_Data) == 0x000300, "Member 'UW_QuickPlayPreferences_C::Save_Data' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, Option_Changed) == 0x000308, "Member 'UW_QuickPlayPreferences_C::Option_Changed' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, TagFilters) == 0x000318, "Member 'UW_QuickPlayPreferences_C::TagFilters' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, LanguageMap) == 0x000328, "Member 'UW_QuickPlayPreferences_C::LanguageMap' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, RequestClose) == 0x000378, "Member 'UW_QuickPlayPreferences_C::RequestClose' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, AnyFilterText) == 0x000388, "Member 'UW_QuickPlayPreferences_C::AnyFilterText' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, GameModeDisplay) == 0x0003A0, "Member 'UW_QuickPlayPreferences_C::GameModeDisplay' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, ElapsedTimeRange) == 0x0003F0, "Member 'UW_QuickPlayPreferences_C::ElapsedTimeRange' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, PlaystyleTags) == 0x000400, "Member 'UW_QuickPlayPreferences_C::PlaystyleTags' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, ExperienceTags) == 0x000410, "Member 'UW_QuickPlayPreferences_C::ExperienceTags' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, MapRotationTags) == 0x000420, "Member 'UW_QuickPlayPreferences_C::MapRotationTags' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, QPTypeTags) == 0x000430, "Member 'UW_QuickPlayPreferences_C::QPTypeTags' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, GameModeOptions) == 0x000440, "Member 'UW_QuickPlayPreferences_C::GameModeOptions' has a wrong offset!");
static_assert(offsetof(UW_QuickPlayPreferences_C, GameModeTags) == 0x000450, "Member 'UW_QuickPlayPreferences_C::GameModeTags' has a wrong offset!");

}

