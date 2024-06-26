#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TerritoryControl_Bar

#include "Basic.hpp"

#include "W_TerritoryControl_Bar_classes.hpp"
#include "W_TerritoryControl_Bar_parameters.hpp"


namespace SDK
{

// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.ExecuteUbergraph_W_TerritoryControl_Bar
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TerritoryControl_Bar_C::ExecuteUbergraph_W_TerritoryControl_Bar(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "ExecuteUbergraph_W_TerritoryControl_Bar");

	Params::W_TerritoryControl_Bar_C_ExecuteUbergraph_W_TerritoryControl_Bar Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.Team Changed Event
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQTeamState*                     OldTeam                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQTeamState*                     NewTeam                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TerritoryControl_Bar_C::Team_Changed_Event(class ASQTeamState* OldTeam, class ASQTeamState* NewTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "Team Changed Event");

	Params::W_TerritoryControl_Bar_C_Team_Changed_Event Parms{};

	Parms.OldTeam = OldTeam;
	Parms.NewTeam = NewTeam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.Bind Team Change
// (BlueprintCallable, BlueprintEvent)

void UW_TerritoryControl_Bar_C::Bind_Team_Change()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "Bind Team Change");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_TerritoryControl_Bar_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TerritoryControl_Bar_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "Tick");

	Params::W_TerritoryControl_Bar_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TerritoryControl_Bar.W_TerritoryControl_Bar_C.Set Flags
// (BlueprintCallable, BlueprintEvent)

void UW_TerritoryControl_Bar_C::Set_Flags()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TerritoryControl_Bar_C", "Set Flags");

	UObject::ProcessEvent(Func, nullptr);
}

}

