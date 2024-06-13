#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VoteLevel

#include "Basic.hpp"

#include "UMG_VoteLevel_classes.hpp"
#include "UMG_VoteLevel_parameters.hpp"


namespace SDK
{

// Function UMG_VoteLevel.UMG_VoteLevel_C.ExecuteUbergraph_UMG_VoteLevel
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteLevel_C::ExecuteUbergraph_UMG_VoteLevel(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "ExecuteUbergraph_UMG_VoteLevel");

	Params::UMG_VoteLevel_C_ExecuteUbergraph_UMG_VoteLevel Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.OnSetup
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             TeamName                                               (BlueprintVisible, BlueprintReadOnly, Parm)
// class FName                             Param_PlayerName                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteLevel_C::OnSetup(const class FText& TeamName, class FName Param_PlayerName)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "OnSetup");

	Params::UMG_VoteLevel_C_OnSetup Parms{};

	Parms.TeamName = std::move(TeamName);
	Parms.Param_PlayerName = Param_PlayerName;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.SetVoteScreenActive
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Activated                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_VoteLevel_C::SetVoteScreenActive(bool Activated)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "SetVoteScreenActive");

	Params::UMG_VoteLevel_C_SetVoteScreenActive Parms{};

	Parms.Activated = Activated;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.OnVoteEnded
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FSQChoice                        Winner                                                 (BlueprintVisible, BlueprintReadOnly, Parm, NoDestructor)

void UUMG_VoteLevel_C::OnVoteEnded(class USQVoteSessionClient* VoteSession, const struct FSQChoice& Winner)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "OnVoteEnded");

	Params::UMG_VoteLevel_C_OnVoteEnded Parms{};

	Parms.VoteSession = VoteSession;
	Parms.Winner = std::move(Winner);

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.OnVoteUpdated
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   PlayerCurrentVoteCount                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteLevel_C::OnVoteUpdated(class USQVoteSessionClient* VoteSession, int32 PlayerCurrentVoteCount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "OnVoteUpdated");

	Params::UMG_VoteLevel_C_OnVoteUpdated Parms{};

	Parms.VoteSession = VoteSession;
	Parms.PlayerCurrentVoteCount = PlayerCurrentVoteCount;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.OnVoteStarted
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    VotePossible                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_VoteLevel_C::OnVoteStarted(class USQVoteSessionClient* VoteSession, bool VotePossible)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "OnVoteStarted");

	Params::UMG_VoteLevel_C_OnVoteStarted Parms{};

	Parms.VoteSession = VoteSession;
	Parms.VotePossible = VotePossible;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.Generate Items
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             Vote_Session                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteLevel_C::Generate_Items(class USQVoteSessionClient* Vote_Session)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "Generate Items");

	Params::UMG_VoteLevel_C_Generate_Items Parms{};

	Parms.Vote_Session = Vote_Session;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.Update Choices
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Player_Current_Votes_Count                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteLevel_C::Update_Choices(class USQVoteSessionClient* VoteSession, int32 Player_Current_Votes_Count)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "Update Choices");

	Params::UMG_VoteLevel_C_Update_Choices Parms{};

	Parms.VoteSession = VoteSession;
	Parms.Player_Current_Votes_Count = Player_Current_Votes_Count;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteLevel.UMG_VoteLevel_C.Display Result
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             Vote_Session                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FSQChoice                        Winner                                                 (BlueprintVisible, BlueprintReadOnly, Parm, NoDestructor)

void UUMG_VoteLevel_C::Display_Result(class USQVoteSessionClient* Vote_Session, const struct FSQChoice& Winner)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteLevel_C", "Display Result");

	Params::UMG_VoteLevel_C_Display_Result Parms{};

	Parms.Vote_Session = Vote_Session;
	Parms.Winner = std::move(Winner);

	UObject::ProcessEvent(Func, &Parms);
}

}
