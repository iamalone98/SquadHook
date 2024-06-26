#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_InfantrySandbags

#include "Basic.hpp"

#include "BP_InfantrySandbags_classes.hpp"
#include "BP_InfantrySandbags_parameters.hpp"


namespace SDK
{

// Function BP_InfantrySandbags.BP_InfantrySandbags_C.ExecuteUbergraph_BP_InfantrySandbags
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_InfantrySandbags_C::ExecuteUbergraph_BP_InfantrySandbags(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_InfantrySandbags_C", "ExecuteUbergraph_BP_InfantrySandbags");

	Params::BP_InfantrySandbags_C_ExecuteUbergraph_BP_InfantrySandbags Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_InfantrySandbags.BP_InfantrySandbags_C.ReceiveDestroyed
// (Event, Public, BlueprintEvent)

void ABP_InfantrySandbags_C::ReceiveDestroyed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_InfantrySandbags_C", "ReceiveDestroyed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_InfantrySandbags.BP_InfantrySandbags_C.RemovedFromPlayersPlacedList
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_InfantrySandbags_C::RemovedFromPlayersPlacedList()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_InfantrySandbags_C", "RemovedFromPlayersPlacedList");

	UObject::ProcessEvent(Func, nullptr);
}

}

