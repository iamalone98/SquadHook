#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_Frontline

#include "Basic.hpp"

#include "BP_MapMarker_Frontline_classes.hpp"
#include "BP_MapMarker_Frontline_parameters.hpp"


namespace SDK
{

// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.ExecuteUbergraph_BP_MapMarker_Frontline
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapMarker_Frontline_C::ExecuteUbergraph_BP_MapMarker_Frontline(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "ExecuteUbergraph_BP_MapMarker_Frontline");

	Params::BP_MapMarker_Frontline_C_ExecuteUbergraph_BP_MapMarker_Frontline Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.OnHasFadedChanged
// (Event, Public, BlueprintEvent)

void UBP_MapMarker_Frontline_C::OnHasFadedChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "OnHasFadedChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.OnMapCoreChanged
// (BlueprintCallable, BlueprintEvent)

void UBP_MapMarker_Frontline_C::OnMapCoreChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "OnMapCoreChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.OnMapZoom
// (BlueprintCallable, BlueprintEvent)

void UBP_MapMarker_Frontline_C::OnMapZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "OnMapZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MapMarker_Frontline_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.RefreshVisibility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapMarker_Frontline_C::RefreshVisibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "RefreshVisibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapMarker_Frontline.BP_MapMarker_Frontline_C.InitDirectorMarker
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MapMarker_Frontline_C::InitDirectorMarker()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_Frontline_C", "InitDirectorMarker");

	UObject::ProcessEvent(Func, nullptr);
}

}

