#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BoatWaterMovement

#include "Basic.hpp"

#include "BP_BoatWaterMovement_classes.hpp"
#include "BP_BoatWaterMovement_parameters.hpp"


namespace SDK
{

// Function BP_BoatWaterMovement.BP_BoatWaterMovement_C.ExecuteUbergraph_BP_BoatWaterMovement
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_BoatWaterMovement_C::ExecuteUbergraph_BP_BoatWaterMovement(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BoatWaterMovement_C", "ExecuteUbergraph_BP_BoatWaterMovement");

	Params::BP_BoatWaterMovement_C_ExecuteUbergraph_BP_BoatWaterMovement Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_BoatWaterMovement.BP_BoatWaterMovement_C.ApplyMovement
// (Event, Public, BlueprintCallable, BlueprintEvent)

void UBP_BoatWaterMovement_C::ApplyMovement()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BoatWaterMovement_C", "ApplyMovement");

	UObject::ProcessEvent(Func, nullptr);
}

}
