#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericRifle_SingleLoad

#include "Basic.hpp"

#include "BP_GenericRifle_SingleLoad_classes.hpp"
#include "BP_GenericRifle_SingleLoad_parameters.hpp"


namespace SDK
{

// Function BP_GenericRifle_SingleLoad.BP_GenericRifle_SingleLoad_C.ExecuteUbergraph_BP_GenericRifle_SingleLoad
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericRifle_SingleLoad_C::ExecuteUbergraph_BP_GenericRifle_SingleLoad(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericRifle_SingleLoad_C", "ExecuteUbergraph_BP_GenericRifle_SingleLoad");

	Params::BP_GenericRifle_SingleLoad_C_ExecuteUbergraph_BP_GenericRifle_SingleLoad Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericRifle_SingleLoad.BP_GenericRifle_SingleLoad_C.BlueprintOnReload
// (Event, Protected, BlueprintEvent)

void ABP_GenericRifle_SingleLoad_C::BlueprintOnReload()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericRifle_SingleLoad_C", "BlueprintOnReload");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericRifle_SingleLoad.BP_GenericRifle_SingleLoad_C.BlueprintOnPreReload
// (Event, Protected, BlueprintEvent)

void ABP_GenericRifle_SingleLoad_C::BlueprintOnPreReload()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericRifle_SingleLoad_C", "BlueprintOnPreReload");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericRifle_SingleLoad.BP_GenericRifle_SingleLoad_C.ReceiveTick
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   DeltaSeconds                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericRifle_SingleLoad_C::ReceiveTick(float DeltaSeconds)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericRifle_SingleLoad_C", "ReceiveTick");

	Params::BP_GenericRifle_SingleLoad_C_ReceiveTick Parms{};

	Parms.DeltaSeconds = DeltaSeconds;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericRifle_SingleLoad.BP_GenericRifle_SingleLoad_C.BP_UpdateSingleRoundReloadAnimation
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void ABP_GenericRifle_SingleLoad_C::BP_UpdateSingleRoundReloadAnimation()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericRifle_SingleLoad_C", "BP_UpdateSingleRoundReloadAnimation");

	UObject::ProcessEvent(Func, nullptr);
}

}
