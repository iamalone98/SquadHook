#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialEmptyEntry

#include "Basic.hpp"

#include "RadialEmptyEntry_classes.hpp"
#include "RadialEmptyEntry_parameters.hpp"


namespace SDK
{

// Function RadialEmptyEntry.RadialEmptyEntry_C.ExecuteUbergraph_RadialEmptyEntry
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialEmptyEntry_C::ExecuteUbergraph_RadialEmptyEntry(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialEmptyEntry_C", "ExecuteUbergraph_RadialEmptyEntry");

	Params::RadialEmptyEntry_C_ExecuteUbergraph_RadialEmptyEntry Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialEmptyEntry.RadialEmptyEntry_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void URadialEmptyEntry_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialEmptyEntry_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}
