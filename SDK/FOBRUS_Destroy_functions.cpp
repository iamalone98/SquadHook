#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FOBRUS_Destroy

#include "Basic.hpp"

#include "FOBRUS_Destroy_classes.hpp"
#include "FOBRUS_Destroy_parameters.hpp"


namespace SDK
{

// Function FOBRUS_Destroy.FOBRUS_Destroy_C.ExecuteUbergraph_FOBRUS_Destroy
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AFOBRUS_Destroy_C::ExecuteUbergraph_FOBRUS_Destroy(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FOBRUS_Destroy_C", "ExecuteUbergraph_FOBRUS_Destroy");

	Params::FOBRUS_Destroy_C_ExecuteUbergraph_FOBRUS_Destroy Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function FOBRUS_Destroy.FOBRUS_Destroy_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void AFOBRUS_Destroy_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FOBRUS_Destroy_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

