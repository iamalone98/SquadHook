#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MagazineGroupWidget

#include "Basic.hpp"

#include "MagazineGroupWidget_classes.hpp"
#include "MagazineGroupWidget_parameters.hpp"


namespace SDK
{

// Function MagazineGroupWidget.MagazineGroupWidget_C.ExecuteUbergraph_MagazineGroupWidget
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UMagazineGroupWidget_C::ExecuteUbergraph_MagazineGroupWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MagazineGroupWidget_C", "ExecuteUbergraph_MagazineGroupWidget");

	Params::MagazineGroupWidget_C_ExecuteUbergraph_MagazineGroupWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MagazineGroupWidget.MagazineGroupWidget_C.BPInit
// (Event, Public, BlueprintEvent)

void UMagazineGroupWidget_C::BPInit()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MagazineGroupWidget_C", "BPInit");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MagazineGroupWidget.MagazineGroupWidget_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UMagazineGroupWidget_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MagazineGroupWidget_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}
