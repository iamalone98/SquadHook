#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetHelipad

#include "Basic.hpp"

#include "BP_MapWidgetHelipad_classes.hpp"
#include "BP_MapWidgetHelipad_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetHelipad.BP_MapWidgetHelipad_C.ExecuteUbergraph_BP_MapWidgetHelipad
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetHelipad_C::ExecuteUbergraph_BP_MapWidgetHelipad(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetHelipad_C", "ExecuteUbergraph_BP_MapWidgetHelipad");

	Params::BP_MapWidgetHelipad_C_ExecuteUbergraph_BP_MapWidgetHelipad Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetHelipad.BP_MapWidgetHelipad_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetHelipad_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetHelipad_C", "OnScaleChanged");

	Params::BP_MapWidgetHelipad_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}

}
