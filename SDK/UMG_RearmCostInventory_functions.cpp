#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_RearmCostInventory

#include "Basic.hpp"

#include "UMG_RearmCostInventory_classes.hpp"
#include "UMG_RearmCostInventory_parameters.hpp"


namespace SDK
{

// Function UMG_RearmCostInventory.UMG_RearmCostInventory_C.ExecuteUbergraph_UMG_RearmCostInventory
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_RearmCostInventory_C::ExecuteUbergraph_UMG_RearmCostInventory(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_RearmCostInventory_C", "ExecuteUbergraph_UMG_RearmCostInventory");

	Params::UMG_RearmCostInventory_C_ExecuteUbergraph_UMG_RearmCostInventory Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_RearmCostInventory.UMG_RearmCostInventory_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_RearmCostInventory_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_RearmCostInventory_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_RearmCostInventory.UMG_RearmCostInventory_C.UpdateRearmCost
// (BlueprintCallable, BlueprintEvent)

void UUMG_RearmCostInventory_C::UpdateRearmCost()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_RearmCostInventory_C", "UpdateRearmCost");

	UObject::ProcessEvent(Func, nullptr);
}

}

