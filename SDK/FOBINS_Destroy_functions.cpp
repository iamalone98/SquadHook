#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FOBINS_Destroy

#include "Basic.hpp"

#include "FOBINS_Destroy_classes.hpp"
#include "FOBINS_Destroy_parameters.hpp"


namespace SDK
{

// Function FOBINS_Destroy.FOBINS_Destroy_C.ExecuteUbergraph_FOBINS_Destroy
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AFOBINS_Destroy_C::ExecuteUbergraph_FOBINS_Destroy(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FOBINS_Destroy_C", "ExecuteUbergraph_FOBINS_Destroy");

	Params::FOBINS_Destroy_C_ExecuteUbergraph_FOBINS_Destroy Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function FOBINS_Destroy.FOBINS_Destroy_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void AFOBINS_Destroy_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FOBINS_Destroy_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

