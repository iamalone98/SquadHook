#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RearmMenu

#include "Basic.hpp"

#include "BP_RearmMenu_classes.hpp"
#include "BP_RearmMenu_parameters.hpp"


namespace SDK
{

// Function BP_RearmMenu.BP_RearmMenu_C.ExecuteUbergraph_BP_RearmMenu
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RearmMenu_C::ExecuteUbergraph_BP_RearmMenu(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RearmMenu_C", "ExecuteUbergraph_BP_RearmMenu");

	Params::BP_RearmMenu_C_ExecuteUbergraph_BP_RearmMenu Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RearmMenu.BP_RearmMenu_C.CreateChildWidgets
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                BaseRadialMenu                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RearmMenu_C::CreateChildWidgets(class UBaseRadialMenu_C* BaseRadialMenu)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RearmMenu_C", "CreateChildWidgets");

	Params::BP_RearmMenu_C_CreateChildWidgets Parms{};

	Parms.BaseRadialMenu = BaseRadialMenu;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RearmMenu.BP_RearmMenu_C.CreateWidgets
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                InputPin                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RearmMenu_C::CreateWidgets(class UBaseRadialMenu_C* InputPin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RearmMenu_C", "CreateWidgets");

	Params::BP_RearmMenu_C_CreateWidgets Parms{};

	Parms.InputPin = InputPin;

	UObject::ProcessEvent(Func, &Parms);
}

}

