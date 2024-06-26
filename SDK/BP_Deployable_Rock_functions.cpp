#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Deployable_Rock

#include "Basic.hpp"

#include "BP_Deployable_Rock_classes.hpp"
#include "BP_Deployable_Rock_parameters.hpp"


namespace SDK
{

// Function BP_Deployable_Rock.BP_Deployable_Rock_C.ExecuteUbergraph_BP_Deployable_Rock
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Rock_C::ExecuteUbergraph_BP_Deployable_Rock(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Rock_C", "ExecuteUbergraph_BP_Deployable_Rock");

	Params::BP_Deployable_Rock_C_ExecuteUbergraph_BP_Deployable_Rock Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Rock.BP_Deployable_Rock_C.RemovedFromPlayersPlacedList
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Rock_C::RemovedFromPlayersPlacedList()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Rock_C", "RemovedFromPlayersPlacedList");

	UObject::ProcessEvent(Func, nullptr);
}

}

