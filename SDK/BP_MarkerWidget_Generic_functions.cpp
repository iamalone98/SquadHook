#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_Generic

#include "Basic.hpp"

#include "BP_MarkerWidget_Generic_classes.hpp"
#include "BP_MarkerWidget_Generic_parameters.hpp"


namespace SDK
{

// Function BP_MarkerWidget_Generic.BP_MarkerWidget_Generic_C.ExecuteUbergraph_BP_MarkerWidget_Generic
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Generic_C::ExecuteUbergraph_BP_MarkerWidget_Generic(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Generic_C", "ExecuteUbergraph_BP_MarkerWidget_Generic");

	Params::BP_MarkerWidget_Generic_C_ExecuteUbergraph_BP_MarkerWidget_Generic Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_Generic.BP_MarkerWidget_Generic_C.Find SQ Map Icon
// (BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Generic_C::Find_SQ_Map_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Generic_C", "Find SQ Map Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Generic.BP_MarkerWidget_Generic_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MarkerWidget_Generic_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Generic_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Generic.BP_MarkerWidget_Generic_C.Get_MarkerImage_Brush_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSlateBrush                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateBrush UBP_MarkerWidget_Generic_C::Get_MarkerImage_Brush_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Generic_C", "Get_MarkerImage_Brush_0");

	Params::BP_MarkerWidget_Generic_C_Get_MarkerImage_Brush_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
