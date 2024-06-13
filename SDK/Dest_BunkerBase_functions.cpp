#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Dest_BunkerBase

#include "Basic.hpp"

#include "Dest_BunkerBase_classes.hpp"
#include "Dest_BunkerBase_parameters.hpp"


namespace SDK
{

// Function Dest_BunkerBase.Dest_BunkerBase_C.ExecuteUbergraph_Dest_BunkerBase
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ADest_BunkerBase_C::ExecuteUbergraph_Dest_BunkerBase(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Dest_BunkerBase_C", "ExecuteUbergraph_Dest_BunkerBase");

	Params::Dest_BunkerBase_C_ExecuteUbergraph_Dest_BunkerBase Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Dest_BunkerBase.Dest_BunkerBase_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ADest_BunkerBase_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Dest_BunkerBase_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

