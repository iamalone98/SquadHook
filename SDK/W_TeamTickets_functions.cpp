#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TeamTickets

#include "Basic.hpp"

#include "W_TeamTickets_classes.hpp"
#include "W_TeamTickets_parameters.hpp"


namespace SDK
{

// Function W_TeamTickets.W_TeamTickets_C.ExecuteUbergraph_W_TeamTickets
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamTickets_C::ExecuteUbergraph_W_TeamTickets(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "ExecuteUbergraph_W_TeamTickets");

	Params::W_TeamTickets_C_ExecuteUbergraph_W_TeamTickets Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamTickets.W_TeamTickets_C.Refresh
// (BlueprintCallable, BlueprintEvent)

void UW_TeamTickets_C::Refresh()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "Refresh");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamTickets.W_TeamTickets_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_TeamTickets_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamTickets.W_TeamTickets_C.GetBleedComponent
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    IsValid                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UGraphNodeBasedBleedComponent_C*  BleedComponent                                         (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamTickets_C::GetBleedComponent(bool* IsValid, class UGraphNodeBasedBleedComponent_C** BleedComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "GetBleedComponent");

	Params::W_TeamTickets_C_GetBleedComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (IsValid != nullptr)
		*IsValid = Parms.IsValid;

	if (BleedComponent != nullptr)
		*BleedComponent = Parms.BleedComponent;
}


// Function W_TeamTickets.W_TeamTickets_C.UpdateCurrentTeam
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    TeamChanged                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_TeamTickets_C::UpdateCurrentTeam(bool* TeamChanged)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "UpdateCurrentTeam");

	Params::W_TeamTickets_C_UpdateCurrentTeam Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (TeamChanged != nullptr)
		*TeamChanged = Parms.TeamChanged;
}


// Function W_TeamTickets.W_TeamTickets_C.UpdateTickets
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_TeamTickets_C::UpdateTickets()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "UpdateTickets");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamTickets.W_TeamTickets_C.UpdateFlag
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_TeamTickets_C::UpdateFlag()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamTickets_C", "UpdateFlag");

	UObject::ProcessEvent(Func, nullptr);
}

}
