#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Director_Frontline

#include "Basic.hpp"

#include "W_Director_Frontline_classes.hpp"
#include "W_Director_Frontline_parameters.hpp"


namespace SDK
{

// Function W_Director_Frontline.W_Director_Frontline_C.ExecuteUbergraph_W_Director_Frontline
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Director_Frontline_C::ExecuteUbergraph_W_Director_Frontline(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Director_Frontline_C", "ExecuteUbergraph_W_Director_Frontline");

	Params::W_Director_Frontline_C_ExecuteUbergraph_W_Director_Frontline Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Director_Frontline.W_Director_Frontline_C.Update Tiling
// (BlueprintCallable, BlueprintEvent)

void UW_Director_Frontline_C::Update_Tiling()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Director_Frontline_C", "Update Tiling");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Director_Frontline.W_Director_Frontline_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Director_Frontline_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Director_Frontline_C", "Tick");

	Params::W_Director_Frontline_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Director_Frontline.W_Director_Frontline_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_Director_Frontline_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Director_Frontline_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}
