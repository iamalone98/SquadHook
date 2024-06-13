#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_HelicopterInputDisplay

#include "Basic.hpp"

#include "W_HelicopterInputDisplay_classes.hpp"
#include "W_HelicopterInputDisplay_parameters.hpp"


namespace SDK
{

// Function W_HelicopterInputDisplay.W_HelicopterInputDisplay_C.ExecuteUbergraph_W_HelicopterInputDisplay
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_HelicopterInputDisplay_C::ExecuteUbergraph_W_HelicopterInputDisplay(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_HelicopterInputDisplay_C", "ExecuteUbergraph_W_HelicopterInputDisplay");

	Params::W_HelicopterInputDisplay_C_ExecuteUbergraph_W_HelicopterInputDisplay Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_HelicopterInputDisplay.W_HelicopterInputDisplay_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_HelicopterInputDisplay_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_HelicopterInputDisplay_C", "Tick");

	Params::W_HelicopterInputDisplay_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_HelicopterInputDisplay.W_HelicopterInputDisplay_C.InitializeMeter
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// TScriptInterface<class ISQHelicopterInstruments>ParentVehicle                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_HelicopterInputDisplay_C::InitializeMeter(TScriptInterface<class ISQHelicopterInstruments> ParentVehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_HelicopterInputDisplay_C", "InitializeMeter");

	Params::W_HelicopterInputDisplay_C_InitializeMeter Parms{};

	Parms.ParentVehicle = ParentVehicle;

	UObject::ProcessEvent(Func, &Parms);
}

}
