#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmotesMenu_RadialEntry

#include "Basic.hpp"

#include "BP_EmotesMenu_RadialEntry_classes.hpp"
#include "BP_EmotesMenu_RadialEntry_parameters.hpp"


namespace SDK
{

// Function BP_EmotesMenu_RadialEntry.BP_EmotesMenu_RadialEntry_C.ExecuteUbergraph_BP_EmotesMenu_RadialEntry
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_EmotesMenu_RadialEntry_C::ExecuteUbergraph_BP_EmotesMenu_RadialEntry(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmotesMenu_RadialEntry_C", "ExecuteUbergraph_BP_EmotesMenu_RadialEntry");

	Params::BP_EmotesMenu_RadialEntry_C_ExecuteUbergraph_BP_EmotesMenu_RadialEntry Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_EmotesMenu_RadialEntry.BP_EmotesMenu_RadialEntry_C.OnClicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_EmotesMenu_RadialEntry_C::OnClicked(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmotesMenu_RadialEntry_C", "OnClicked");

	Params::BP_EmotesMenu_RadialEntry_C_OnClicked Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_EmotesMenu_RadialEntry.BP_EmotesMenu_RadialEntry_C.CanClick
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQPlayerController*              PC                                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    bCanClick                                              (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// TArray<class FString>                   ReturnValue                                            (Parm, OutParm, ReturnParm)

TArray<class FString> UBP_EmotesMenu_RadialEntry_C::CanClick(class ASQPlayerController* PC, bool* bCanClick)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmotesMenu_RadialEntry_C", "CanClick");

	Params::BP_EmotesMenu_RadialEntry_C_CanClick Parms{};

	Parms.PC = PC;

	UObject::ProcessEvent(Func, &Parms);

	if (bCanClick != nullptr)
		*bCanClick = Parms.bCanClick;

	return Parms.ReturnValue;
}

}
