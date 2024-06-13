#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L85A2_SUSAT

#include "Basic.hpp"

#include "BP_L85A2_SUSAT_classes.hpp"
#include "BP_L85A2_SUSAT_parameters.hpp"


namespace SDK
{

// Function BP_L85A2_SUSAT.BP_L85A2_SUSAT_C.ExecuteUbergraph_BP_L85A2_SUSAT
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_L85A2_SUSAT_C::ExecuteUbergraph_BP_L85A2_SUSAT(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_L85A2_SUSAT_C", "ExecuteUbergraph_BP_L85A2_SUSAT");

	Params::BP_L85A2_SUSAT_C_ExecuteUbergraph_BP_L85A2_SUSAT Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_L85A2_SUSAT.BP_L85A2_SUSAT_C.StopModifyZeroing
// (Event, Public, BlueprintEvent)

void ABP_L85A2_SUSAT_C::StopModifyZeroing()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_L85A2_SUSAT_C", "StopModifyZeroing");

	UObject::ProcessEvent(Func, nullptr);
}

}
