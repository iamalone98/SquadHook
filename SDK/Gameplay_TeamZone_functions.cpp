#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Gameplay_TeamZone

#include "Basic.hpp"

#include "Gameplay_TeamZone_classes.hpp"
#include "Gameplay_TeamZone_parameters.hpp"


namespace SDK
{

// Function Gameplay_TeamZone.Gameplay_TeamZone_C.OverlapPushAway__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void AGameplay_TeamZone_C::OverlapPushAway__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Gameplay_TeamZone_C", "OverlapPushAway__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function Gameplay_TeamZone.Gameplay_TeamZone_C.Init__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void AGameplay_TeamZone_C::Init__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Gameplay_TeamZone_C", "Init__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function Gameplay_TeamZone.Gameplay_TeamZone_C.ExecuteUbergraph_Gameplay_TeamZone
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AGameplay_TeamZone_C::ExecuteUbergraph_Gameplay_TeamZone(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Gameplay_TeamZone_C", "ExecuteUbergraph_Gameplay_TeamZone");

	Params::Gameplay_TeamZone_C_ExecuteUbergraph_Gameplay_TeamZone Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Gameplay_TeamZone.Gameplay_TeamZone_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void AGameplay_TeamZone_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Gameplay_TeamZone_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

