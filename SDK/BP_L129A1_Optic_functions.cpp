#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_L129A1_Optic

#include "Basic.hpp"

#include "BP_L129A1_Optic_classes.hpp"
#include "BP_L129A1_Optic_parameters.hpp"


namespace SDK
{

// Function BP_L129A1_Optic.BP_L129A1_Optic_C.ExecuteUbergraph_BP_L129A1_Optic
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_L129A1_Optic_C::ExecuteUbergraph_BP_L129A1_Optic(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_L129A1_Optic_C", "ExecuteUbergraph_BP_L129A1_Optic");

	Params::BP_L129A1_Optic_C_ExecuteUbergraph_BP_L129A1_Optic Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_L129A1_Optic.BP_L129A1_Optic_C.StopModifyZeroing
// (Event, Public, BlueprintEvent)

void ABP_L129A1_Optic_C::StopModifyZeroing()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_L129A1_Optic_C", "StopModifyZeroing");

	UObject::ProcessEvent(Func, nullptr);
}

}

