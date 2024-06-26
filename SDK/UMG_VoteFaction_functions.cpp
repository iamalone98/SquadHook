#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VoteFaction

#include "Basic.hpp"

#include "UMG_VoteFaction_classes.hpp"
#include "UMG_VoteFaction_parameters.hpp"


namespace SDK
{

// Function UMG_VoteFaction.UMG_VoteFaction_C.FactionInfoRequested__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             Faction                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::FactionInfoRequested__DelegateSignature(class FName Faction)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "FactionInfoRequested__DelegateSignature");

	Params::UMG_VoteFaction_C_FactionInfoRequested__DelegateSignature Parms{};

	Parms.Faction = Faction;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.ExecuteUbergraph_UMG_VoteFaction
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::ExecuteUbergraph_UMG_VoteFaction(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "ExecuteUbergraph_UMG_VoteFaction");

	Params::UMG_VoteFaction_C_ExecuteUbergraph_UMG_VoteFaction Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "Tick");

	Params::UMG_VoteFaction_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.SetVoteScreenActive
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Activated                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_VoteFaction_C::SetVoteScreenActive(bool Activated)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "SetVoteScreenActive");

	Params::UMG_VoteFaction_C_SetVoteScreenActive Parms{};

	Parms.Activated = Activated;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.OnVoteStarted
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    VotePossible                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_VoteFaction_C::OnVoteStarted(class USQVoteSessionClient* VoteSession, bool VotePossible)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "OnVoteStarted");

	Params::UMG_VoteFaction_C_OnVoteStarted Parms{};

	Parms.VoteSession = VoteSession;
	Parms.VotePossible = VotePossible;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.OnVoteUpdated
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   PlayerCurrentVoteCount                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::OnVoteUpdated(class USQVoteSessionClient* VoteSession, int32 PlayerCurrentVoteCount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "OnVoteUpdated");

	Params::UMG_VoteFaction_C_OnVoteUpdated Parms{};

	Parms.VoteSession = VoteSession;
	Parms.PlayerCurrentVoteCount = PlayerCurrentVoteCount;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.OnInitialized
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_VoteFaction_C::OnInitialized()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "OnInitialized");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.GetTeamWidget
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   TeamId                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UUMG_VoteFactionTeam_C*           TeamWidget                                             (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::GetTeamWidget(int32 TeamId, class UUMG_VoteFactionTeam_C** TeamWidget)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "GetTeamWidget");

	Params::UMG_VoteFaction_C_GetTeamWidget Parms{};

	Parms.TeamId = TeamId;

	UObject::ProcessEvent(Func, &Parms);

	if (TeamWidget != nullptr)
		*TeamWidget = Parms.TeamWidget;
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.SelectWidget
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSession*                   VoteSession                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UUMG_VoteFactionTeam_C*           TeamWidget                                             (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::SelectWidget(class USQVoteSession* VoteSession, class UUMG_VoteFactionTeam_C** TeamWidget)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "SelectWidget");

	Params::UMG_VoteFaction_C_SelectWidget Parms{};

	Parms.VoteSession = VoteSession;

	UObject::ProcessEvent(Func, &Parms);

	if (TeamWidget != nullptr)
		*TeamWidget = Parms.TeamWidget;
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.DeActivateAll
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VoteFaction_C::DeActivateAll()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "DeActivateAll");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.UpdateActivations
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UUMG_VoteFactionTeam_C*           VoteFactionTeam                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Active                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_VoteFaction_C::UpdateActivations(class UUMG_VoteFactionTeam_C* VoteFactionTeam, bool Active)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "UpdateActivations");

	Params::UMG_VoteFaction_C_UpdateActivations Parms{};

	Parms.VoteFactionTeam = VoteFactionTeam;
	Parms.Active = Active;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.SetupSubElements
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VoteFaction_C::SetupSubElements()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "SetupSubElements");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.Generate Items
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             Vote_Session                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::Generate_Items(class USQVoteSessionClient* Vote_Session)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "Generate Items");

	Params::UMG_VoteFaction_C_Generate_Items Parms{};

	Parms.Vote_Session = Vote_Session;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.UpdateChoiceByID
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             ChoiceId                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::UpdateChoiceByID(class FName ChoiceId)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "UpdateChoiceByID");

	Params::UMG_VoteFaction_C_UpdateChoiceByID Parms{};

	Parms.ChoiceId = ChoiceId;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.OnChoiceSelected
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             Choice                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::OnChoiceSelected(class FName Choice)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "OnChoiceSelected");

	Params::UMG_VoteFaction_C_OnChoiceSelected Parms{};

	Parms.Choice = Choice;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.Update Choices
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSessionClient*             Vote_Session                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Player_Current_Vote_Count                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::Update_Choices(class USQVoteSessionClient* Vote_Session, int32 Player_Current_Vote_Count)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "Update Choices");

	Params::UMG_VoteFaction_C_Update_Choices Parms{};

	Parms.Vote_Session = Vote_Session;
	Parms.Player_Current_Vote_Count = Player_Current_Vote_Count;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VoteFaction.UMG_VoteFaction_C.OnInfoSelected
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             ChoiceId                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VoteFaction_C::OnInfoSelected(class FName ChoiceId)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VoteFaction_C", "OnInfoSelected");

	Params::UMG_VoteFaction_C_OnInfoSelected Parms{};

	Parms.ChoiceId = ChoiceId;

	UObject::ProcessEvent(Func, &Parms);
}

}

