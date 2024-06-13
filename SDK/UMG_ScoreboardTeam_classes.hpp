#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_ScoreboardTeam

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_ScoreboardTeam.UMG_ScoreboardTeam_C
// 0x00F0 (0x04D0 - 0x03E0)
class UUMG_ScoreboardTeam_C final : public USQScoreboardTeam
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x03E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 BPColoredHeaderBarImage;                           // 0x03E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BPColoredHeaderTabImage;                           // 0x03F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         BPEndOfRoundHorizontal;                            // 0x03F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USpacer*                                BPEnemyTeamPingAligner;                            // 0x0400(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BPFlagImage;                                       // 0x0408(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           BpNonSquadPlayersCanvasPanel;                      // 0x0410(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USpacer*                                BPNotEndOfRoundSpacer;                             // 0x0418(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BpObjectiveScore;                                  // 0x0420(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BpPlayerNumberText;                                // 0x0428(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGridPanel*                             BPPlayersGrid;                                     // 0x0430(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPRemainingTicketsText;                            // 0x0438(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_ScoreboardTeamScore_C*             BPScoreboardTeamScore;                             // 0x0440(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPScoreText;                                       // 0x0448(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BPSquadScore;                                      // 0x0450(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGridPanel*                             BPSquadsGrid;                                      // 0x0458(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         BPTeamHorizontalBox;                               // 0x0460(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             BPTeamNameText;                                    // 0x0468(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BPTicketIcon;                                      // 0x0470(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           BPTopVerticalBox;                                  // 0x0478(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Deaths;                                            // 0x0480(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Heal;                                              // 0x0488(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0490(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x0498(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Incaps;                                            // 0x04A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Ping;                                              // 0x04A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Revive;                                            // 0x04B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TB_Kills;                                          // 0x04B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Kit;                                            // 0x04C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 VehicleImage;                                      // 0x04C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_ScoreboardTeam(int32 EntryPoint);
	void BPInit();
	void Construct();
	class UWidget* Get_VehicleImage_ToolTipWidget_0();
	class UWidget* Get_TB_Kit_ToolTipWidget_0();
	class UWidget* Get_TB_Kills_ToolTipWidget_0();
	class UWidget* Get_Deaths_ToolTipWidget_0();
	class UWidget* Get_Incaps_ToolTipWidget_0();
	class UWidget* Get_Revive_ToolTipWidget_0();
	class UWidget* Get_Heal_ToolTipWidget_0();
	class UWidget* Get_BPSquadScore_ToolTipWidget_0();
	class UWidget* Get_BpObjectiveScore_ToolTipWidget_0();
	class UWidget* Get_BPScoreText_ToolTipWidget_0();
	class UWidget* Get_Ping_ToolTipWidget_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_ScoreboardTeam_C">();
	}
	static class UUMG_ScoreboardTeam_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_ScoreboardTeam_C>();
	}
};
static_assert(alignof(UUMG_ScoreboardTeam_C) == 0x000008, "Wrong alignment on UUMG_ScoreboardTeam_C");
static_assert(sizeof(UUMG_ScoreboardTeam_C) == 0x0004D0, "Wrong size on UUMG_ScoreboardTeam_C");
static_assert(offsetof(UUMG_ScoreboardTeam_C, UberGraphFrame) == 0x0003E0, "Member 'UUMG_ScoreboardTeam_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPColoredHeaderBarImage) == 0x0003E8, "Member 'UUMG_ScoreboardTeam_C::BPColoredHeaderBarImage' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPColoredHeaderTabImage) == 0x0003F0, "Member 'UUMG_ScoreboardTeam_C::BPColoredHeaderTabImage' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPEndOfRoundHorizontal) == 0x0003F8, "Member 'UUMG_ScoreboardTeam_C::BPEndOfRoundHorizontal' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPEnemyTeamPingAligner) == 0x000400, "Member 'UUMG_ScoreboardTeam_C::BPEnemyTeamPingAligner' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPFlagImage) == 0x000408, "Member 'UUMG_ScoreboardTeam_C::BPFlagImage' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BpNonSquadPlayersCanvasPanel) == 0x000410, "Member 'UUMG_ScoreboardTeam_C::BpNonSquadPlayersCanvasPanel' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPNotEndOfRoundSpacer) == 0x000418, "Member 'UUMG_ScoreboardTeam_C::BPNotEndOfRoundSpacer' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BpObjectiveScore) == 0x000420, "Member 'UUMG_ScoreboardTeam_C::BpObjectiveScore' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BpPlayerNumberText) == 0x000428, "Member 'UUMG_ScoreboardTeam_C::BpPlayerNumberText' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPPlayersGrid) == 0x000430, "Member 'UUMG_ScoreboardTeam_C::BPPlayersGrid' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPRemainingTicketsText) == 0x000438, "Member 'UUMG_ScoreboardTeam_C::BPRemainingTicketsText' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPScoreboardTeamScore) == 0x000440, "Member 'UUMG_ScoreboardTeam_C::BPScoreboardTeamScore' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPScoreText) == 0x000448, "Member 'UUMG_ScoreboardTeam_C::BPScoreText' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPSquadScore) == 0x000450, "Member 'UUMG_ScoreboardTeam_C::BPSquadScore' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPSquadsGrid) == 0x000458, "Member 'UUMG_ScoreboardTeam_C::BPSquadsGrid' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPTeamHorizontalBox) == 0x000460, "Member 'UUMG_ScoreboardTeam_C::BPTeamHorizontalBox' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPTeamNameText) == 0x000468, "Member 'UUMG_ScoreboardTeam_C::BPTeamNameText' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPTicketIcon) == 0x000470, "Member 'UUMG_ScoreboardTeam_C::BPTicketIcon' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, BPTopVerticalBox) == 0x000478, "Member 'UUMG_ScoreboardTeam_C::BPTopVerticalBox' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Deaths) == 0x000480, "Member 'UUMG_ScoreboardTeam_C::Deaths' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Heal) == 0x000488, "Member 'UUMG_ScoreboardTeam_C::Heal' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Image_0) == 0x000490, "Member 'UUMG_ScoreboardTeam_C::Image_0' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Image_1) == 0x000498, "Member 'UUMG_ScoreboardTeam_C::Image_1' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Incaps) == 0x0004A0, "Member 'UUMG_ScoreboardTeam_C::Incaps' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Ping) == 0x0004A8, "Member 'UUMG_ScoreboardTeam_C::Ping' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, Revive) == 0x0004B0, "Member 'UUMG_ScoreboardTeam_C::Revive' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, TB_Kills) == 0x0004B8, "Member 'UUMG_ScoreboardTeam_C::TB_Kills' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, TB_Kit) == 0x0004C0, "Member 'UUMG_ScoreboardTeam_C::TB_Kit' has a wrong offset!");
static_assert(offsetof(UUMG_ScoreboardTeam_C, VehicleImage) == 0x0004C8, "Member 'UUMG_ScoreboardTeam_C::VehicleImage' has a wrong offset!");

}
