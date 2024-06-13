#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Marker_Widget_Objective

#include "Basic.hpp"

#include "BP_Marker_Widget_Objective_classes.hpp"
#include "BP_Marker_Widget_Objective_parameters.hpp"


namespace SDK
{

// Function BP_Marker_Widget_Objective.BP_Marker_Widget_Objective_C.ExecuteUbergraph_BP_Marker_Widget_Objective
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_Marker_Widget_Objective_C::ExecuteUbergraph_BP_Marker_Widget_Objective(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Marker_Widget_Objective_C", "ExecuteUbergraph_BP_Marker_Widget_Objective");

	Params::BP_Marker_Widget_Objective_C_ExecuteUbergraph_BP_Marker_Widget_Objective Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Marker_Widget_Objective.BP_Marker_Widget_Objective_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_Marker_Widget_Objective_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Marker_Widget_Objective_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Marker_Widget_Objective.BP_Marker_Widget_Objective_C.Get_MarkerImage_Brush_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSlateBrush                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateBrush UBP_Marker_Widget_Objective_C::Get_MarkerImage_Brush_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Marker_Widget_Objective_C", "Get_MarkerImage_Brush_0");

	Params::BP_Marker_Widget_Objective_C_Get_MarkerImage_Brush_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_Marker_Widget_Objective.BP_Marker_Widget_Objective_C.GetText_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UBP_Marker_Widget_Objective_C::GetText_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Marker_Widget_Objective_C", "GetText_0");

	Params::BP_Marker_Widget_Objective_C_GetText_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
