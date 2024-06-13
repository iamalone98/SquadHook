#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_WorldActions_Entry

#include "Basic.hpp"

#include "W_WorldActions_Entry_classes.hpp"
#include "W_WorldActions_Entry_parameters.hpp"


namespace SDK
{

// Function W_WorldActions_Entry.W_WorldActions_Entry_C.ExecuteUbergraph_W_WorldActions_Entry
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_WorldActions_Entry_C::ExecuteUbergraph_W_WorldActions_Entry(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_WorldActions_Entry_C", "ExecuteUbergraph_W_WorldActions_Entry");

	Params::W_WorldActions_Entry_C_ExecuteUbergraph_W_WorldActions_Entry Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_WorldActions_Entry.W_WorldActions_Entry_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_WorldActions_Entry_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_WorldActions_Entry_C", "PreConstruct");

	Params::W_WorldActions_Entry_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_WorldActions_Entry.W_WorldActions_Entry_C.BndEvt__W_WorldActions_Entry_CheckBox_89_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bIsChecked                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_WorldActions_Entry_C::BndEvt__W_WorldActions_Entry_CheckBox_89_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature(bool bIsChecked)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_WorldActions_Entry_C", "BndEvt__W_WorldActions_Entry_CheckBox_89_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature");

	Params::W_WorldActions_Entry_C_BndEvt__W_WorldActions_Entry_CheckBox_89_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature Parms{};

	Parms.bIsChecked = bIsChecked;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_WorldActions_Entry.W_WorldActions_Entry_C.MarkChecked
// (Public, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// bool                                    Checked                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_WorldActions_Entry_C::MarkChecked(bool Checked) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_WorldActions_Entry_C", "MarkChecked");

	Params::W_WorldActions_Entry_C_MarkChecked Parms{};

	Parms.Checked = Checked;

	UObject::ProcessEvent(Func, &Parms);
}

}

