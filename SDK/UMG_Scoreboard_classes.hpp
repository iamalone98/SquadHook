#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Scoreboard

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_Scoreboard.UMG_Scoreboard_C
// 0x0178 (0x0490 - 0x0318)
class UUMG_Scoreboard_C final : public USQScoreboard
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0318(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Blink;                                             // 0x0320(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       Fade;                                              // 0x0328(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Border_Fav;                                        // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_FavPulse;                                   // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Bottom;                                            // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPCurrentGamemodeTextBlock;                        // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BpCurrentMapTextBlock;                             // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPGameResultTextBlock;                             // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BpGameTimeClockImage;                              // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPNextMapTextBlock;                                // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPPlayerCountTextBlock;                            // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BpRemainingGameTimeText;                           // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPRemainingTicketsText;                            // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_ScoreboardTeam_C*                  BPScoreboardEnemy;                                 // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_ScoreboardTeam_C*                  BPScoreboardFriendly;                              // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPServerNameTextBlock;                             // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BPTickImage;                                       // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPTickTextBlock;                                   // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    Button_Favourite;                                  // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         EndRoundTimer;                                     // 0x03B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_0;                                   // 0x03C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x03C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_4;                                           // 0x03D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        MainSwitcher;                                      // 0x03D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             PostMatchStep;                                     // 0x03E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           ResultCanvas;                                      // 0x03E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_2;                                        // 0x03F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_4;                                        // 0x03F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     SquadChatButton;                                   // 0x0400(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Timer;                                          // 0x0408(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        TimerSwitcher;                                     // 0x0410(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_ScoreboardVoteButton_C*            VoteScreenButton;                                  // 0x0418(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UNamedSlot*                             VoteSlot;                                          // 0x0420(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             VoteTimer;                                         // 0x0428(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_VoipOwningPlayer_C*                  W_VoipOwningPlayer;                                // 0x0430(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   TickRateText;                                      // 0x0438(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	int32                                         CurrentGameTime;                                   // 0x0450(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3CDA[0x4];                                     // 0x0454(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   DefaultFavoriteText;                               // 0x0458(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class FText                                   MarkFavoriteText;                                  // 0x0470(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          SquadVoipOnly;                                     // 0x0488(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_UMG_Scoreboard(int32 EntryPoint);
	void BndEvt__UMG_Scoreboard_Button_Favourite_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void SwitchToMainScreen(int32 Param_Index);
	void Destruct();
	void Play_Fade_Animation();
	void BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void CustomTickEvent();
	void BPInit();
	void Construct();
	void BndEvt__UMG_Scoreboard_UMG_ScoreboardVoteButton_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button);
	void UpdateServerFPSText();
	void UpdateScaling();
	void IsFavourite(bool* Valid, bool* Favourite);
	void Toggle_Favourite(bool Is_Fave);
	void UpdateFavouriteName();
	void IsValidFavourite(TArray<class FString>& Favourites, class FString& UniqueID, bool Licensed, bool* Valid);
	void Update_Favourite();
	void InsertVoteWidget(class UUserWidget* VoteWidget);
	void UpdateSquadChatButton(bool Selected);
	void ShowVotingScreen();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_Scoreboard_C">();
	}
	static class UUMG_Scoreboard_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_Scoreboard_C>();
	}
};
static_assert(alignof(UUMG_Scoreboard_C) == 0x000008, "Wrong alignment on UUMG_Scoreboard_C");
static_assert(sizeof(UUMG_Scoreboard_C) == 0x000490, "Wrong size on UUMG_Scoreboard_C");
static_assert(offsetof(UUMG_Scoreboard_C, UberGraphFrame) == 0x000318, "Member 'UUMG_Scoreboard_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Blink) == 0x000320, "Member 'UUMG_Scoreboard_C::Blink' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Fade) == 0x000328, "Member 'UUMG_Scoreboard_C::Fade' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Border_Fav) == 0x000330, "Member 'UUMG_Scoreboard_C::Border_Fav' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Border_FavPulse) == 0x000338, "Member 'UUMG_Scoreboard_C::Border_FavPulse' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Bottom) == 0x000340, "Member 'UUMG_Scoreboard_C::Bottom' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPCurrentGamemodeTextBlock) == 0x000348, "Member 'UUMG_Scoreboard_C::BPCurrentGamemodeTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BpCurrentMapTextBlock) == 0x000350, "Member 'UUMG_Scoreboard_C::BpCurrentMapTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPGameResultTextBlock) == 0x000358, "Member 'UUMG_Scoreboard_C::BPGameResultTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BpGameTimeClockImage) == 0x000360, "Member 'UUMG_Scoreboard_C::BpGameTimeClockImage' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPNextMapTextBlock) == 0x000368, "Member 'UUMG_Scoreboard_C::BPNextMapTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPPlayerCountTextBlock) == 0x000370, "Member 'UUMG_Scoreboard_C::BPPlayerCountTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BpRemainingGameTimeText) == 0x000378, "Member 'UUMG_Scoreboard_C::BpRemainingGameTimeText' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPRemainingTicketsText) == 0x000380, "Member 'UUMG_Scoreboard_C::BPRemainingTicketsText' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPScoreboardEnemy) == 0x000388, "Member 'UUMG_Scoreboard_C::BPScoreboardEnemy' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPScoreboardFriendly) == 0x000390, "Member 'UUMG_Scoreboard_C::BPScoreboardFriendly' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPServerNameTextBlock) == 0x000398, "Member 'UUMG_Scoreboard_C::BPServerNameTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPTickImage) == 0x0003A0, "Member 'UUMG_Scoreboard_C::BPTickImage' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, BPTickTextBlock) == 0x0003A8, "Member 'UUMG_Scoreboard_C::BPTickTextBlock' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Button_Favourite) == 0x0003B0, "Member 'UUMG_Scoreboard_C::Button_Favourite' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, EndRoundTimer) == 0x0003B8, "Member 'UUMG_Scoreboard_C::EndRoundTimer' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, HorizontalBox_0) == 0x0003C0, "Member 'UUMG_Scoreboard_C::HorizontalBox_0' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Image_0) == 0x0003C8, "Member 'UUMG_Scoreboard_C::Image_0' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, Image_4) == 0x0003D0, "Member 'UUMG_Scoreboard_C::Image_4' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, MainSwitcher) == 0x0003D8, "Member 'UUMG_Scoreboard_C::MainSwitcher' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, PostMatchStep) == 0x0003E0, "Member 'UUMG_Scoreboard_C::PostMatchStep' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, ResultCanvas) == 0x0003E8, "Member 'UUMG_Scoreboard_C::ResultCanvas' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, ScaleBox_2) == 0x0003F0, "Member 'UUMG_Scoreboard_C::ScaleBox_2' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, ScaleBox_4) == 0x0003F8, "Member 'UUMG_Scoreboard_C::ScaleBox_4' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, SquadChatButton) == 0x000400, "Member 'UUMG_Scoreboard_C::SquadChatButton' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, TB_Timer) == 0x000408, "Member 'UUMG_Scoreboard_C::TB_Timer' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, TimerSwitcher) == 0x000410, "Member 'UUMG_Scoreboard_C::TimerSwitcher' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, VoteScreenButton) == 0x000418, "Member 'UUMG_Scoreboard_C::VoteScreenButton' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, VoteSlot) == 0x000420, "Member 'UUMG_Scoreboard_C::VoteSlot' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, VoteTimer) == 0x000428, "Member 'UUMG_Scoreboard_C::VoteTimer' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, W_VoipOwningPlayer) == 0x000430, "Member 'UUMG_Scoreboard_C::W_VoipOwningPlayer' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, TickRateText) == 0x000438, "Member 'UUMG_Scoreboard_C::TickRateText' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, CurrentGameTime) == 0x000450, "Member 'UUMG_Scoreboard_C::CurrentGameTime' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, DefaultFavoriteText) == 0x000458, "Member 'UUMG_Scoreboard_C::DefaultFavoriteText' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, MarkFavoriteText) == 0x000470, "Member 'UUMG_Scoreboard_C::MarkFavoriteText' has a wrong offset!");
static_assert(offsetof(UUMG_Scoreboard_C, SquadVoipOnly) == 0x000488, "Member 'UUMG_Scoreboard_C::SquadVoipOnly' has a wrong offset!");

}

