#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TeamSelectUpdated

#include "Basic.hpp"

#include "ESQLayerSpecialTag_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "ESQLayerSize_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_TeamSelectUpdated.W_TeamSelectUpdated_C
// 0x0240 (0x04A0 - 0x0260)
class UW_TeamSelectUpdated_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       TeamTwoSelected;                                   // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       TeamOneSelected;                                   // 0x0270(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Background;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BottomBorder;                                      // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCircularThrobber*                      CircularThrobber_174;                              // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    CloseModeInfoButton;                               // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_FactionUnitDetailsScreen_C*          FactionVoteDetails;                                // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             FlagsDesc;                                         // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             FlagsNameText;                                     // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             FlagsValue;                                        // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             GamemodeTitle;                                     // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             GamemodeTitleText;                                 // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             LightingText_1;                                    // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             LightingValue;                                     // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             MapNameText;                                       // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_MapPreviewPOI_C*                   MapPreviewPOI;                                     // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        MapSwitcher;                                       // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 MenuBackgroundCrosses;                             // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    ModeInfoButton;                                    // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UNamedSlot*                             NamedSlot_ModeWidget;                              // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     NAV_SERVERRULES;                                   // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     NAV_SQUADS;                                        // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     NAV_TEAMSELECT;                                    // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_ModeInfo;                                  // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_TeamOne;                                   // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_TeamTwo;                                   // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             ServerNameText;                                    // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SizeText;                                          // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SizeValue;                                         // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SpecialValue;                                      // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    TeamContinueButton;                                // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_TeamInfoUpdated_C*                   TeamOne;                                           // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TeamOneBottomBorder;                               // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TeamOneTopBorder;                                  // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_TeamInfoUpdated_C*                   TeamTwo;                                           // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TeamTwoBottomBorder;                               // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TeamTwoTopBorder;                                  // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_MapName;                                 // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_Objective;                               // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TicketsValue;                                      // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TopBorder;                                         // 0x03B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         TopNavigation;                                     // 0x03C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_GameTime_C*                          W_GameTime;                                        // 0x03C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_ModeInfo;                           // 0x03D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	struct FTimerHandle                           Timer_Handle;                                      // 0x03D8(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Selected_Border_Texture;                           // 0x03E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Unselected_Border_Texture;                         // 0x03E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Selected_Team;                                     // 0x03F0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4926[0x4];                                     // 0x03F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Team_Selected;                                     // 0x03F8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TMap<ESQLayerSpecialTag, class FText>         LayerSpecialTagsTranslation;                       // 0x0408(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<class FText>                           FlagsTexts;                                        // 0x0458(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             OnNavigationSquads;                                // 0x0468(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnNavigationTeamSelect;                            // 0x0478(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnNavigationServerRules;                           // 0x0488(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	int32                                         TicketsTeam1;                                      // 0x0498(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         TicketsTeam2;                                      // 0x049C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void Team_Selected__DelegateSignature(int32 Selected_Team_Id);
	void OnNavigationSquads__DelegateSignature();
	void OnNavigationTeamSelect__DelegateSignature();
	void OnNavigationServerRules__DelegateSignature();
	void ExecuteUbergraph_W_TeamSelectUpdated(int32 EntryPoint);
	void BndEvt__W_TeamSelectUpdated_TeamTwo_K2Node_ComponentBoundEvent_3_OnSizeValueChanged__DelegateSignature(float NewParam);
	void BndEvt__W_TeamSelectUpdated_TeamOne_K2Node_ComponentBoundEvent_2_OnSizeValueChanged__DelegateSignature(float NewParam);
	void BndEvt__W_TeamSelectUpdated_FactionVoteDetails_K2Node_ComponentBoundEvent_11_CloseWidget__DelegateSignature();
	void CloseModeInfo();
	void BndEvt__W_TeamSelectUpdated_NAV_SERVERRULES_K2Node_ComponentBoundEvent_9_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__W_TeamSelectUpdated_NAV_SQUADS_K2Node_ComponentBoundEvent_8_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__W_TeamSelectUpdated_NAV_TEAMSELECT_K2Node_ComponentBoundEvent_7_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void PresentLayerMap(TSoftObjectPtr<class UTexture> LayerTexture, class USQLayer* Layer);
	void BndEvt__W_TeamSelectUpdated_CloseModeInfoButton_K2Node_ComponentBoundEvent_6_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_TeamSelectUpdated_ModeInfoButton_K2Node_ComponentBoundEvent_5_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void BndEvt__W_TeamSelectUpdated_TeamContinueButton_K2Node_ComponentBoundEvent_4_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__W_TeamSelectUpdated_TeamTwo_K2Node_ComponentBoundEvent_1_OnTeamChangePressed__DelegateSignature(class ASQTeamState* SelectedTeam);
	void BndEvt__W_TeamSelectUpdated_TeamOne_K2Node_ComponentBoundEvent_0_OnTeamChangePressed__DelegateSignature(class ASQTeamState* SelectedTeam);
	void On_Enter_Clicked();
	void Grab_Game_Info();
	void Construct();
	void OnLoaded_B39BC97346D55E3567336A86D0B4918A(class UObject* Loaded);
	void Refresh();
	void Init_Info(const struct FSQGameModeEntry& GameMode);
	class FText Get_Server_Name();
	void Format_Gamemode_Name(const class FText& Text, class FText* Result);
	void Create_Map_Material(class UTexture2D* Map_Texture, class UMaterialInstance** NewParam);
	void Get_Gamemode(struct FSQGameModeEntry* Gamemode_Entry, bool* Valid);
	void Set_Border_Selected(class UBorder* Border, bool Selected);
	void Grab_Initial_Selected_Team();
	void Change_Team_Selection(int32 Team_Index);
	void ConcatSpecialTags(class FText& Source, class FText& Add);
	void UpdateSpecialTags(class UBP_SQLayer_C* Layer);
	void UpdateLighting(class UBP_SQLayer_C* Layer);
	void UpdateGameModeData(class UBP_SQLayer_C* Layer);
	void ShowFactionInfo(class USQFactionSetup* Faction, int32 TeamId);
	ESlateVisibility Get_TeamContinueButton_Visibility_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_TeamSelectUpdated_C">();
	}
	static class UW_TeamSelectUpdated_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_TeamSelectUpdated_C>();
	}
};
static_assert(alignof(UW_TeamSelectUpdated_C) == 0x000008, "Wrong alignment on UW_TeamSelectUpdated_C");
static_assert(sizeof(UW_TeamSelectUpdated_C) == 0x0004A0, "Wrong size on UW_TeamSelectUpdated_C");
static_assert(offsetof(UW_TeamSelectUpdated_C, UberGraphFrame) == 0x000260, "Member 'UW_TeamSelectUpdated_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamTwoSelected) == 0x000268, "Member 'UW_TeamSelectUpdated_C::TeamTwoSelected' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamOneSelected) == 0x000270, "Member 'UW_TeamSelectUpdated_C::TeamOneSelected' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Background) == 0x000278, "Member 'UW_TeamSelectUpdated_C::Background' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, BottomBorder) == 0x000280, "Member 'UW_TeamSelectUpdated_C::BottomBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, CircularThrobber_174) == 0x000288, "Member 'UW_TeamSelectUpdated_C::CircularThrobber_174' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, CloseModeInfoButton) == 0x000290, "Member 'UW_TeamSelectUpdated_C::CloseModeInfoButton' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, FactionVoteDetails) == 0x000298, "Member 'UW_TeamSelectUpdated_C::FactionVoteDetails' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, FlagsDesc) == 0x0002A0, "Member 'UW_TeamSelectUpdated_C::FlagsDesc' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, FlagsNameText) == 0x0002A8, "Member 'UW_TeamSelectUpdated_C::FlagsNameText' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, FlagsValue) == 0x0002B0, "Member 'UW_TeamSelectUpdated_C::FlagsValue' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, GamemodeTitle) == 0x0002B8, "Member 'UW_TeamSelectUpdated_C::GamemodeTitle' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, GamemodeTitleText) == 0x0002C0, "Member 'UW_TeamSelectUpdated_C::GamemodeTitleText' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Image) == 0x0002C8, "Member 'UW_TeamSelectUpdated_C::Image' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Image_1) == 0x0002D0, "Member 'UW_TeamSelectUpdated_C::Image_1' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, LightingText_1) == 0x0002D8, "Member 'UW_TeamSelectUpdated_C::LightingText_1' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, LightingValue) == 0x0002E0, "Member 'UW_TeamSelectUpdated_C::LightingValue' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, MapNameText) == 0x0002E8, "Member 'UW_TeamSelectUpdated_C::MapNameText' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, MapPreviewPOI) == 0x0002F0, "Member 'UW_TeamSelectUpdated_C::MapPreviewPOI' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, MapSwitcher) == 0x0002F8, "Member 'UW_TeamSelectUpdated_C::MapSwitcher' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, MenuBackgroundCrosses) == 0x000300, "Member 'UW_TeamSelectUpdated_C::MenuBackgroundCrosses' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, ModeInfoButton) == 0x000308, "Member 'UW_TeamSelectUpdated_C::ModeInfoButton' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, NamedSlot_ModeWidget) == 0x000310, "Member 'UW_TeamSelectUpdated_C::NamedSlot_ModeWidget' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, NAV_SERVERRULES) == 0x000318, "Member 'UW_TeamSelectUpdated_C::NAV_SERVERRULES' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, NAV_SQUADS) == 0x000320, "Member 'UW_TeamSelectUpdated_C::NAV_SQUADS' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, NAV_TEAMSELECT) == 0x000328, "Member 'UW_TeamSelectUpdated_C::NAV_TEAMSELECT' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Overlay_ModeInfo) == 0x000330, "Member 'UW_TeamSelectUpdated_C::Overlay_ModeInfo' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Overlay_TeamOne) == 0x000338, "Member 'UW_TeamSelectUpdated_C::Overlay_TeamOne' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Overlay_TeamTwo) == 0x000340, "Member 'UW_TeamSelectUpdated_C::Overlay_TeamTwo' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, ServerNameText) == 0x000348, "Member 'UW_TeamSelectUpdated_C::ServerNameText' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, SizeText) == 0x000350, "Member 'UW_TeamSelectUpdated_C::SizeText' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, SizeValue) == 0x000358, "Member 'UW_TeamSelectUpdated_C::SizeValue' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, SpecialValue) == 0x000360, "Member 'UW_TeamSelectUpdated_C::SpecialValue' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamContinueButton) == 0x000368, "Member 'UW_TeamSelectUpdated_C::TeamContinueButton' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamOne) == 0x000370, "Member 'UW_TeamSelectUpdated_C::TeamOne' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamOneBottomBorder) == 0x000378, "Member 'UW_TeamSelectUpdated_C::TeamOneBottomBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamOneTopBorder) == 0x000380, "Member 'UW_TeamSelectUpdated_C::TeamOneTopBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamTwo) == 0x000388, "Member 'UW_TeamSelectUpdated_C::TeamTwo' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamTwoBottomBorder) == 0x000390, "Member 'UW_TeamSelectUpdated_C::TeamTwoBottomBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TeamTwoTopBorder) == 0x000398, "Member 'UW_TeamSelectUpdated_C::TeamTwoTopBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TextBlock_MapName) == 0x0003A0, "Member 'UW_TeamSelectUpdated_C::TextBlock_MapName' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TextBlock_Objective) == 0x0003A8, "Member 'UW_TeamSelectUpdated_C::TextBlock_Objective' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TicketsValue) == 0x0003B0, "Member 'UW_TeamSelectUpdated_C::TicketsValue' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TopBorder) == 0x0003B8, "Member 'UW_TeamSelectUpdated_C::TopBorder' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TopNavigation) == 0x0003C0, "Member 'UW_TeamSelectUpdated_C::TopNavigation' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, W_GameTime) == 0x0003C8, "Member 'UW_TeamSelectUpdated_C::W_GameTime' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, WidgetSwitcher_ModeInfo) == 0x0003D0, "Member 'UW_TeamSelectUpdated_C::WidgetSwitcher_ModeInfo' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Timer_Handle) == 0x0003D8, "Member 'UW_TeamSelectUpdated_C::Timer_Handle' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Selected_Border_Texture) == 0x0003E0, "Member 'UW_TeamSelectUpdated_C::Selected_Border_Texture' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Unselected_Border_Texture) == 0x0003E8, "Member 'UW_TeamSelectUpdated_C::Unselected_Border_Texture' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Selected_Team) == 0x0003F0, "Member 'UW_TeamSelectUpdated_C::Selected_Team' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, Team_Selected) == 0x0003F8, "Member 'UW_TeamSelectUpdated_C::Team_Selected' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, LayerSpecialTagsTranslation) == 0x000408, "Member 'UW_TeamSelectUpdated_C::LayerSpecialTagsTranslation' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, FlagsTexts) == 0x000458, "Member 'UW_TeamSelectUpdated_C::FlagsTexts' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, OnNavigationSquads) == 0x000468, "Member 'UW_TeamSelectUpdated_C::OnNavigationSquads' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, OnNavigationTeamSelect) == 0x000478, "Member 'UW_TeamSelectUpdated_C::OnNavigationTeamSelect' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, OnNavigationServerRules) == 0x000488, "Member 'UW_TeamSelectUpdated_C::OnNavigationServerRules' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TicketsTeam1) == 0x000498, "Member 'UW_TeamSelectUpdated_C::TicketsTeam1' has a wrong offset!");
static_assert(offsetof(UW_TeamSelectUpdated_C, TicketsTeam2) == 0x00049C, "Member 'UW_TeamSelectUpdated_C::TicketsTeam2' has a wrong offset!");

}

