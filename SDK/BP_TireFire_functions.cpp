#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_TireFire

#include "Basic.hpp"

#include "BP_TireFire_classes.hpp"
#include "BP_TireFire_parameters.hpp"


namespace SDK
{

// Function BP_TireFire.BP_TireFire_C.ExecuteUbergraph_BP_TireFire
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_TireFire_C::ExecuteUbergraph_BP_TireFire(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_TireFire_C", "ExecuteUbergraph_BP_TireFire");

	Params::BP_TireFire_C_ExecuteUbergraph_BP_TireFire Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_TireFire.BP_TireFire_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_TireFire_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_TireFire_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_TireFire.BP_TireFire_C.BP_OnStateChangeClient
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// ESQBuildState                           OldBuildState                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_TireFire_C::BP_OnStateChangeClient(ESQBuildState OldBuildState)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_TireFire_C", "BP_OnStateChangeClient");

	Params::BP_TireFire_C_BP_OnStateChangeClient Parms{};

	Parms.OldBuildState = OldBuildState;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_TireFire.BP_TireFire_C.FadeAudio__UpdateFunc
// (BlueprintEvent)

void ABP_TireFire_C::FadeAudio__UpdateFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_TireFire_C", "FadeAudio__UpdateFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_TireFire.BP_TireFire_C.FadeAudio__FinishedFunc
// (BlueprintEvent)

void ABP_TireFire_C::FadeAudio__FinishedFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_TireFire_C", "FadeAudio__FinishedFunc");

	UObject::ProcessEvent(Func, nullptr);
}

}

