#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetCameraman

#include "Basic.hpp"

#include "BP_MapWidgetCameraman_classes.hpp"
#include "BP_MapWidgetCameraman_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetCameraman.BP_MapWidgetCameraman_C.ExecuteUbergraph_BP_MapWidgetCameraman
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetCameraman_C::ExecuteUbergraph_BP_MapWidgetCameraman(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetCameraman_C", "ExecuteUbergraph_BP_MapWidgetCameraman");

	Params::BP_MapWidgetCameraman_C_ExecuteUbergraph_BP_MapWidgetCameraman Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetCameraman.BP_MapWidgetCameraman_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetCameraman_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetCameraman_C", "OnScaleChanged");

	Params::BP_MapWidgetCameraman_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetCameraman.BP_MapWidgetCameraman_C.OnTintValueChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetCameraman_C::OnTintValueChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetCameraman_C", "OnTintValueChanged");

	UObject::ProcessEvent(Func, nullptr);
}

}

