#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapMarker_DirectorLine

#include "Basic.hpp"

#include "W_MapMarker_DirectorLine_classes.hpp"
#include "W_MapMarker_DirectorLine_parameters.hpp"


namespace SDK
{

// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.ExecuteUbergraph_W_MapMarker_DirectorLine
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_MapMarker_DirectorLine_C::ExecuteUbergraph_W_MapMarker_DirectorLine(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "ExecuteUbergraph_W_MapMarker_DirectorLine");

	Params::W_MapMarker_DirectorLine_C_ExecuteUbergraph_W_MapMarker_DirectorLine Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.OnTintChanged
// (Event, Protected, BlueprintEvent)

void UW_MapMarker_DirectorLine_C::OnTintChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "OnTintChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_MapMarker_DirectorLine_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "Tick");

	Params::W_MapMarker_DirectorLine_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.Init Director Marker
// (BlueprintCallable, BlueprintEvent)

void UW_MapMarker_DirectorLine_C::Init_Director_Marker()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "Init Director Marker");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.Update Size
// (Public, BlueprintCallable, BlueprintEvent)

void UW_MapMarker_DirectorLine_C::Update_Size()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "Update Size");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapMarker_DirectorLine.W_MapMarker_DirectorLine_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_MapMarker_DirectorLine_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapMarker_DirectorLine_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}

