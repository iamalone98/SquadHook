#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetAmmoCrate

#include "Basic.hpp"

#include "BP_MapWidgetAmmoCrate_classes.hpp"
#include "BP_MapWidgetAmmoCrate_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetAmmoCrate.BP_MapWidgetAmmoCrate_C.ExecuteUbergraph_BP_MapWidgetAmmoCrate
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetAmmoCrate_C::ExecuteUbergraph_BP_MapWidgetAmmoCrate(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetAmmoCrate_C", "ExecuteUbergraph_BP_MapWidgetAmmoCrate");

	Params::BP_MapWidgetAmmoCrate_C_ExecuteUbergraph_BP_MapWidgetAmmoCrate Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetAmmoCrate.BP_MapWidgetAmmoCrate_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetAmmoCrate_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetAmmoCrate_C", "OnScaleChanged");

	Params::BP_MapWidgetAmmoCrate_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}

}

