#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ReplayObject

#include "Basic.hpp"

#include "BP_ReplayObject_classes.hpp"
#include "BP_ReplayObject_parameters.hpp"


namespace SDK
{

// Function BP_ReplayObject.BP_ReplayObject_C.GetSize
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Result                                                 (Parm, OutParm)

void UBP_ReplayObject_C::GetSize(class FText* Result)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ReplayObject_C", "GetSize");

	Params::BP_ReplayObject_C_GetSize Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Result != nullptr)
		*Result = std::move(Parms.Result);
}

}
