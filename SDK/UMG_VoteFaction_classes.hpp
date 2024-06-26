#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VoteFaction

#include "Basic.hpp"

#include "UMG_VoteBase_classes.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_VoteFaction.UMG_VoteFaction_C
// 0x0040 (0x02B0 - 0x0270)
class UUMG_VoteFaction_C final : public UUMG_VoteBase_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_UMG_VoteFaction_C;                  // 0x0270(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UHorizontalBox*                         HB1;                                               // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HB2;                                               // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USQVoteSessionClient*                   VoteSessionRef;                                    // 0x0288(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UUMG_VoteItem_C*>                ChoicesWidgets;                                    // 0x0290(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	FMulticastInlineDelegateProperty_             FactionInfoRequested;                              // 0x02A0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void FactionInfoRequested__DelegateSignature(class FName Faction);
	void ExecuteUbergraph_UMG_VoteFaction(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void SetVoteScreenActive(bool Activated);
	void OnVoteStarted(class USQVoteSessionClient* VoteSession, bool VotePossible);
	void OnVoteUpdated(class USQVoteSessionClient* VoteSession, int32 PlayerCurrentVoteCount);
	void OnInitialized();
	void GetTeamWidget(int32 TeamId, class UUMG_VoteFactionTeam_C** TeamWidget);
	void SelectWidget(class USQVoteSession* VoteSession, class UUMG_VoteFactionTeam_C** TeamWidget);
	void DeActivateAll();
	void UpdateActivations(class UUMG_VoteFactionTeam_C* VoteFactionTeam, bool Active);
	void SetupSubElements();
	void Generate_Items(class USQVoteSessionClient* Vote_Session);
	void UpdateChoiceByID(class FName ChoiceId);
	void OnChoiceSelected(class FName Choice);
	void Update_Choices(class USQVoteSessionClient* Vote_Session, int32 Player_Current_Vote_Count);
	void OnInfoSelected(class FName ChoiceId);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_VoteFaction_C">();
	}
	static class UUMG_VoteFaction_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_VoteFaction_C>();
	}
};
static_assert(alignof(UUMG_VoteFaction_C) == 0x000008, "Wrong alignment on UUMG_VoteFaction_C");
static_assert(sizeof(UUMG_VoteFaction_C) == 0x0002B0, "Wrong size on UUMG_VoteFaction_C");
static_assert(offsetof(UUMG_VoteFaction_C, UberGraphFrame_UMG_VoteFaction_C) == 0x000270, "Member 'UUMG_VoteFaction_C::UberGraphFrame_UMG_VoteFaction_C' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFaction_C, HB1) == 0x000278, "Member 'UUMG_VoteFaction_C::HB1' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFaction_C, HB2) == 0x000280, "Member 'UUMG_VoteFaction_C::HB2' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFaction_C, VoteSessionRef) == 0x000288, "Member 'UUMG_VoteFaction_C::VoteSessionRef' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFaction_C, ChoicesWidgets) == 0x000290, "Member 'UUMG_VoteFaction_C::ChoicesWidgets' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFaction_C, FactionInfoRequested) == 0x0002A0, "Member 'UUMG_VoteFaction_C::FactionInfoRequested' has a wrong offset!");

}

