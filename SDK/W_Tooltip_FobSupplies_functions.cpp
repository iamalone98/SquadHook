#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Tooltip_FobSupplies

#include "Basic.hpp"

#include "W_Tooltip_FobSupplies_classes.hpp"
#include "W_Tooltip_FobSupplies_parameters.hpp"


namespace SDK
{

// Function W_Tooltip_FobSupplies.W_Tooltip_FobSupplies_C.ExecuteUbergraph_W_Tooltip_FobSupplies
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Tooltip_FobSupplies_C::ExecuteUbergraph_W_Tooltip_FobSupplies(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Tooltip_FobSupplies_C", "ExecuteUbergraph_W_Tooltip_FobSupplies");

	Params::W_Tooltip_FobSupplies_C_ExecuteUbergraph_W_Tooltip_FobSupplies Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Tooltip_FobSupplies.W_Tooltip_FobSupplies_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Tooltip_FobSupplies_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Tooltip_FobSupplies_C", "Tick");

	Params::W_Tooltip_FobSupplies_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}

}

