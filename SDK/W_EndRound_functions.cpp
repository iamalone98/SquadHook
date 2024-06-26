#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_EndRound

#include "Basic.hpp"

#include "W_EndRound_classes.hpp"
#include "W_EndRound_parameters.hpp"


namespace SDK
{

// Function W_EndRound.W_EndRound_C.ExecuteUbergraph_W_EndRound
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_EndRound_C::ExecuteUbergraph_W_EndRound(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "ExecuteUbergraph_W_EndRound");

	Params::W_EndRound_C_ExecuteUbergraph_W_EndRound Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_EndRound.W_EndRound_C.Event Play Team Sounds
// (BlueprintCallable, BlueprintEvent)

void UW_EndRound_C::Event_Play_Team_Sounds()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "Event Play Team Sounds");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_EndRound.W_EndRound_C.HUD Scoreboard
// (BlueprintCallable, BlueprintEvent)

void UW_EndRound_C::HUD_Scoreboard()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "HUD Scoreboard");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_EndRound.W_EndRound_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_EndRound_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_EndRound.W_EndRound_C.OnLoaded_4D00979747334CD613094AA5E0E4B4C2
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UObject*                          Loaded                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_EndRound_C::OnLoaded_4D00979747334CD613094AA5E0E4B4C2(class UObject* Loaded)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "OnLoaded_4D00979747334CD613094AA5E0E4B4C2");

	Params::W_EndRound_C_OnLoaded_4D00979747334CD613094AA5E0E4B4C2 Parms{};

	Parms.Loaded = Loaded;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_EndRound.W_EndRound_C.Init End Round Screen
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_EndRound_C::Init_End_Round_Screen()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_EndRound_C", "Init End Round Screen");

	UObject::ProcessEvent(Func, nullptr);
}

}

