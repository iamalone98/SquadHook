#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQToastWidget

#include "Basic.hpp"

#include "BP_SQToastWidget_classes.hpp"
#include "BP_SQToastWidget_parameters.hpp"


namespace SDK
{

// Function BP_SQToastWidget.BP_SQToastWidget_C.ExecuteUbergraph_BP_SQToastWidget
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_SQToastWidget_C::ExecuteUbergraph_BP_SQToastWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQToastWidget_C", "ExecuteUbergraph_BP_SQToastWidget");

	Params::BP_SQToastWidget_C_ExecuteUbergraph_BP_SQToastWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_SQToastWidget.BP_SQToastWidget_C.ToastTextUpdated_Event
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Param_ToastText                                        (BlueprintVisible, BlueprintReadOnly, Parm)

void UBP_SQToastWidget_C::ToastTextUpdated_Event(const class FText& Param_ToastText)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQToastWidget_C", "ToastTextUpdated_Event");

	Params::BP_SQToastWidget_C_ToastTextUpdated_Event Parms{};

	Parms.Param_ToastText = std::move(Param_ToastText);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_SQToastWidget.BP_SQToastWidget_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_SQToastWidget_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQToastWidget_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}
