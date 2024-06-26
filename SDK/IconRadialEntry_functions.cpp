#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IconRadialEntry

#include "Basic.hpp"

#include "IconRadialEntry_classes.hpp"
#include "IconRadialEntry_parameters.hpp"


namespace SDK
{

// Function IconRadialEntry.IconRadialEntry_C.ExecuteUbergraph_IconRadialEntry
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UIconRadialEntry_C::ExecuteUbergraph_IconRadialEntry(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IconRadialEntry_C", "ExecuteUbergraph_IconRadialEntry");

	Params::IconRadialEntry_C_ExecuteUbergraph_IconRadialEntry Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function IconRadialEntry.IconRadialEntry_C.OnHoverBegin
// (Event, Public, BlueprintCallable, BlueprintEvent)

void UIconRadialEntry_C::OnHoverBegin()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IconRadialEntry_C", "OnHoverBegin");

	UObject::ProcessEvent(Func, nullptr);
}


// Function IconRadialEntry.IconRadialEntry_C.UpdateActiveState
// (Event, Public, BlueprintCallable, BlueprintEvent)

void UIconRadialEntry_C::UpdateActiveState()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IconRadialEntry_C", "UpdateActiveState");

	UObject::ProcessEvent(Func, nullptr);
}


// Function IconRadialEntry.IconRadialEntry_C.BPInit
// (Event, Public, BlueprintEvent)

void UIconRadialEntry_C::BPInit()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IconRadialEntry_C", "BPInit");

	UObject::ProcessEvent(Func, nullptr);
}

}

