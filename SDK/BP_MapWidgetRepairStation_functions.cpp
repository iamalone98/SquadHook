#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetRepairStation

#include "Basic.hpp"

#include "BP_MapWidgetRepairStation_classes.hpp"
#include "BP_MapWidgetRepairStation_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetRepairStation.BP_MapWidgetRepairStation_C.ExecuteUbergraph_BP_MapWidgetRepairStation
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetRepairStation_C::ExecuteUbergraph_BP_MapWidgetRepairStation(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetRepairStation_C", "ExecuteUbergraph_BP_MapWidgetRepairStation");

	Params::BP_MapWidgetRepairStation_C_ExecuteUbergraph_BP_MapWidgetRepairStation Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetRepairStation.BP_MapWidgetRepairStation_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetRepairStation_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetRepairStation_C", "OnScaleChanged");

	Params::BP_MapWidgetRepairStation_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}

}
