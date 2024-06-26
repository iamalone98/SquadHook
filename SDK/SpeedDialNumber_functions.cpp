#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SpeedDialNumber

#include "Basic.hpp"

#include "SpeedDialNumber_classes.hpp"
#include "SpeedDialNumber_parameters.hpp"


namespace SDK
{

// Function SpeedDialNumber.SpeedDialNumber_C.ExecuteUbergraph_SpeedDialNumber
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USpeedDialNumber_C::ExecuteUbergraph_SpeedDialNumber(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SpeedDialNumber_C", "ExecuteUbergraph_SpeedDialNumber");

	Params::SpeedDialNumber_C_ExecuteUbergraph_SpeedDialNumber Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SpeedDialNumber.SpeedDialNumber_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USpeedDialNumber_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SpeedDialNumber_C", "PreConstruct");

	Params::SpeedDialNumber_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}

}

