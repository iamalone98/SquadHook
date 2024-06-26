#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_ScoreboardSquad

#include "Basic.hpp"

#include "UMG_ScoreboardSquad_classes.hpp"
#include "UMG_ScoreboardSquad_parameters.hpp"


namespace SDK
{

// Function UMG_ScoreboardSquad.UMG_ScoreboardSquad_C.ExecuteUbergraph_UMG_ScoreboardSquad
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_ScoreboardSquad_C::ExecuteUbergraph_UMG_ScoreboardSquad(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ScoreboardSquad_C", "ExecuteUbergraph_UMG_ScoreboardSquad");

	Params::UMG_ScoreboardSquad_C_ExecuteUbergraph_UMG_ScoreboardSquad Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_ScoreboardSquad.UMG_ScoreboardSquad_C.UpdateState
// (Event, Public, BlueprintCallable, BlueprintEvent)

void UUMG_ScoreboardSquad_C::UpdateState()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ScoreboardSquad_C", "UpdateState");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_ScoreboardSquad.UMG_ScoreboardSquad_C.BPInit
// (Event, Public, BlueprintEvent)

void UUMG_ScoreboardSquad_C::BPInit()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ScoreboardSquad_C", "BPInit");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_ScoreboardSquad.UMG_ScoreboardSquad_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_ScoreboardSquad_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ScoreboardSquad_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_ScoreboardSquad.UMG_ScoreboardSquad_C.Sort Squad
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UUMG_ScoreboardSquad_C::Sort_Squad()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ScoreboardSquad_C", "Sort Squad");

	UObject::ProcessEvent(Func, nullptr);
}

}

