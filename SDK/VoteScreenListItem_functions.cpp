#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: VoteScreenListItem

#include "Basic.hpp"

#include "VoteScreenListItem_classes.hpp"
#include "VoteScreenListItem_parameters.hpp"


namespace SDK
{

// Function VoteScreenListItem.VoteScreenListItem_C.OnUpdate__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   VoteCount                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    HasVotedFor                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UVoteScreenListItem_C::OnUpdate__DelegateSignature(int32 VoteCount, bool HasVotedFor)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "OnUpdate__DelegateSignature");

	Params::VoteScreenListItem_C_OnUpdate__DelegateSignature Parms{};

	Parms.VoteCount = VoteCount;
	Parms.HasVotedFor = HasVotedFor;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoteScreenListItem.VoteScreenListItem_C.OnEnd__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    IsWinner                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UVoteScreenListItem_C::OnEnd__DelegateSignature(bool IsWinner)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "OnEnd__DelegateSignature");

	Params::VoteScreenListItem_C_OnEnd__DelegateSignature Parms{};

	Parms.IsWinner = IsWinner;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoteScreenListItem.VoteScreenListItem_C.ExecuteUbergraph_VoteScreenListItem
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoteScreenListItem_C::ExecuteUbergraph_VoteScreenListItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "ExecuteUbergraph_VoteScreenListItem");

	Params::VoteScreenListItem_C_ExecuteUbergraph_VoteScreenListItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoteScreenListItem.VoteScreenListItem_C.OnVoteEnded
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSession*                   Param_VoteSession                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FName                             WinnerId                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoteScreenListItem_C::OnVoteEnded(class USQVoteSession* Param_VoteSession, class FName WinnerId)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "OnVoteEnded");

	Params::VoteScreenListItem_C_OnVoteEnded Parms{};

	Parms.Param_VoteSession = Param_VoteSession;
	Parms.WinnerId = WinnerId;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoteScreenListItem.VoteScreenListItem_C.OnVoteUpdated
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQVoteSession*                   Param_VoteSession                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Param_PlayerCurrentVotes                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoteScreenListItem_C::OnVoteUpdated(class USQVoteSession* Param_VoteSession, int32 Param_PlayerCurrentVotes)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "OnVoteUpdated");

	Params::VoteScreenListItem_C_OnVoteUpdated Parms{};

	Parms.Param_VoteSession = Param_VoteSession;
	Parms.Param_PlayerCurrentVotes = Param_PlayerCurrentVotes;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoteScreenListItem.VoteScreenListItem_C.SendVote
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    OutVotedDisplayStatus                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UVoteScreenListItem_C::SendVote(bool* OutVotedDisplayStatus)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoteScreenListItem_C", "SendVote");

	Params::VoteScreenListItem_C_SendVote Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutVotedDisplayStatus != nullptr)
		*OutVotedDisplayStatus = Parms.OutVotedDisplayStatus;
}

}

