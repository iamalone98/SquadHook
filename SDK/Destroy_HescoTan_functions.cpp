#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Destroy_HescoTan

#include "Basic.hpp"

#include "Destroy_HescoTan_classes.hpp"
#include "Destroy_HescoTan_parameters.hpp"


namespace SDK
{

// Function Destroy_HescoTan.Destroy_HescoTan_C.ExecuteUbergraph_Destroy_HescoTan
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ADestroy_HescoTan_C::ExecuteUbergraph_Destroy_HescoTan(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Destroy_HescoTan_C", "ExecuteUbergraph_Destroy_HescoTan");

	Params::Destroy_HescoTan_C_ExecuteUbergraph_Destroy_HescoTan Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Destroy_HescoTan.Destroy_HescoTan_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ADestroy_HescoTan_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Destroy_HescoTan_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

