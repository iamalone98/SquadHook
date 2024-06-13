#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tpku2b_Periscope_reticle

#include "Basic.hpp"

#include "Tpku2b_Periscope_reticle_classes.hpp"
#include "Tpku2b_Periscope_reticle_parameters.hpp"


namespace SDK
{

// Function Tpku2b_Periscope_reticle.Tpku2b_Periscope_reticle_C.ExecuteUbergraph_Tpku2b_Periscope_reticle
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UTpku2b_Periscope_reticle_C::ExecuteUbergraph_Tpku2b_Periscope_reticle(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tpku2b_Periscope_reticle_C", "ExecuteUbergraph_Tpku2b_Periscope_reticle");

	Params::Tpku2b_Periscope_reticle_C_ExecuteUbergraph_Tpku2b_Periscope_reticle Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Tpku2b_Periscope_reticle.Tpku2b_Periscope_reticle_C.UpdateZoomLevelReticle
// (BlueprintCallable, BlueprintEvent)

void UTpku2b_Periscope_reticle_C::UpdateZoomLevelReticle()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tpku2b_Periscope_reticle_C", "UpdateZoomLevelReticle");

	UObject::ProcessEvent(Func, nullptr);
}


// Function Tpku2b_Periscope_reticle.Tpku2b_Periscope_reticle_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UTpku2b_Periscope_reticle_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tpku2b_Periscope_reticle_C", "Tick");

	Params::Tpku2b_Periscope_reticle_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Tpku2b_Periscope_reticle.Tpku2b_Periscope_reticle_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UTpku2b_Periscope_reticle_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tpku2b_Periscope_reticle_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}

