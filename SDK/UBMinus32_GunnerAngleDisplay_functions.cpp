#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UBMinus32_GunnerAngleDisplay

#include "Basic.hpp"

#include "UBMinus32_GunnerAngleDisplay_classes.hpp"
#include "UBMinus32_GunnerAngleDisplay_parameters.hpp"


namespace SDK
{

// Function UB-32_GunnerAngleDisplay.UB-32_GunnerAngleDisplay_C.ExecuteUbergraph_UB-32_GunnerAngleDisplay
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUBMinus32_GunnerAngleDisplay_C::ExecuteUbergraph_UBMinus32_GunnerAngleDisplay(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UB-32_GunnerAngleDisplay_C", "ExecuteUbergraph_UB-32_GunnerAngleDisplay");

	Params::UBMinus32_GunnerAngleDisplay_C_ExecuteUbergraph_UBMinus32_GunnerAngleDisplay Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UB-32_GunnerAngleDisplay.UB-32_GunnerAngleDisplay_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUBMinus32_GunnerAngleDisplay_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UB-32_GunnerAngleDisplay_C", "Tick");

	Params::UBMinus32_GunnerAngleDisplay_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UB-32_GunnerAngleDisplay.UB-32_GunnerAngleDisplay_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUBMinus32_GunnerAngleDisplay_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UB-32_GunnerAngleDisplay_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UB-32_GunnerAngleDisplay.UB-32_GunnerAngleDisplay_C.AngleRotationDisplay
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UUBMinus32_GunnerAngleDisplay_C::AngleRotationDisplay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UB-32_GunnerAngleDisplay_C", "AngleRotationDisplay");

	UObject::ProcessEvent(Func, nullptr);
}

}

