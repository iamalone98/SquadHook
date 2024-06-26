#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Tooltip_CaptureZone

#include "Basic.hpp"

#include "W_Tooltip_CaptureZone_classes.hpp"
#include "W_Tooltip_CaptureZone_parameters.hpp"


namespace SDK
{

// Function W_Tooltip_CaptureZone.W_Tooltip_CaptureZone_C.ExecuteUbergraph_W_Tooltip_CaptureZone
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Tooltip_CaptureZone_C::ExecuteUbergraph_W_Tooltip_CaptureZone(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Tooltip_CaptureZone_C", "ExecuteUbergraph_W_Tooltip_CaptureZone");

	Params::W_Tooltip_CaptureZone_C_ExecuteUbergraph_W_Tooltip_CaptureZone Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Tooltip_CaptureZone.W_Tooltip_CaptureZone_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_Tooltip_CaptureZone_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Tooltip_CaptureZone_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Tooltip_CaptureZone.W_Tooltip_CaptureZone_C.Update Zone Tooltip Text
// (Public, BlueprintCallable, BlueprintEvent)

void UW_Tooltip_CaptureZone_C::Update_Zone_Tooltip_Text()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Tooltip_CaptureZone_C", "Update Zone Tooltip Text");

	UObject::ProcessEvent(Func, nullptr);
}

}

