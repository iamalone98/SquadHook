#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPRadialPopulatorRearmGroup

#include "Basic.hpp"

#include "BPRadialPopulatorRearmGroup_classes.hpp"
#include "BPRadialPopulatorRearmGroup_parameters.hpp"


namespace SDK
{

// Function BPRadialPopulatorRearmGroup.BPRadialPopulatorRearmGroup_C.ExecuteUbergraph_BPRadialPopulatorRearmGroup
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBPRadialPopulatorRearmGroup_C::ExecuteUbergraph_BPRadialPopulatorRearmGroup(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPRadialPopulatorRearmGroup_C", "ExecuteUbergraph_BPRadialPopulatorRearmGroup");

	Params::BPRadialPopulatorRearmGroup_C_ExecuteUbergraph_BPRadialPopulatorRearmGroup Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BPRadialPopulatorRearmGroup.BPRadialPopulatorRearmGroup_C.InitialSetup
// (Protected, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQUserWidget*                    Widget                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBP_RadialItemModel_C*            Model                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBaseRadialMenu_C*                RadialMenu                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBPRadialPopulatorRearmGroup_C::InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPRadialPopulatorRearmGroup_C", "InitialSetup");

	Params::BPRadialPopulatorRearmGroup_C_InitialSetup Parms{};

	Parms.Widget = Widget;
	Parms.Model = Model;
	Parms.RadialMenu = RadialMenu;

	UObject::ProcessEvent(Func, &Parms);
}

}
