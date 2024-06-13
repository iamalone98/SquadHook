#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VoteFactionTeam

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_VoteFactionTeam.UMG_VoteFactionTeam_C
// 0x0028 (0x0288 - 0x0260)
class UUMG_VoteFactionTeam_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UTileView*                              Grid;                                              // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TeamTitle;                                         // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class UVoteScreenListItem_C*>          Choices;                                           // 0x0278(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_UMG_VoteFactionTeam(int32 EntryPoint);
	void SetVoteScreenActive(bool Activated);
	void OnVoteEnded(class USQVoteSessionClient* VoteSession, const struct FSQChoice& Winner);
	void OnVoteUpdated(class USQVoteSessionClient* VoteSession, int32 PlayerCurrentVoteCount);
	void OnVoteStarted(class USQVoteSessionClient* VoteSession, bool VotePossible);
	void OnSetup(const class FText& TeamName, class FName PlayerName);
	void OnVoteUpdatedByID(class FName ChoiceId);
	void Generate_Items(class USQVoteSessionClient* VoteSession);
	void Update_Choices(class USQVoteSessionClient* VoteSession, int32 PlayerCurrentVotesCount);
	void Display_Result(class USQVoteSessionClient* VoteSession, const struct FSQChoice& Winner);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_VoteFactionTeam_C">();
	}
	static class UUMG_VoteFactionTeam_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_VoteFactionTeam_C>();
	}
};
static_assert(alignof(UUMG_VoteFactionTeam_C) == 0x000008, "Wrong alignment on UUMG_VoteFactionTeam_C");
static_assert(sizeof(UUMG_VoteFactionTeam_C) == 0x000288, "Wrong size on UUMG_VoteFactionTeam_C");
static_assert(offsetof(UUMG_VoteFactionTeam_C, UberGraphFrame) == 0x000260, "Member 'UUMG_VoteFactionTeam_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFactionTeam_C, Grid) == 0x000268, "Member 'UUMG_VoteFactionTeam_C::Grid' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFactionTeam_C, TeamTitle) == 0x000270, "Member 'UUMG_VoteFactionTeam_C::TeamTitle' has a wrong offset!");
static_assert(offsetof(UUMG_VoteFactionTeam_C, Choices) == 0x000278, "Member 'UUMG_VoteFactionTeam_C::Choices' has a wrong offset!");

}
