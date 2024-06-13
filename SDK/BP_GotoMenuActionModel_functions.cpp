#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GotoMenuActionModel

#include "Basic.hpp"

#include "BP_GotoMenuActionModel_classes.hpp"
#include "BP_GotoMenuActionModel_parameters.hpp"


namespace SDK
{

// Function BP_GotoMenuActionModel.BP_GotoMenuActionModel_C.ExecuteUbergraph_BP_GotoMenuActionModel
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_GotoMenuActionModel_C::ExecuteUbergraph_BP_GotoMenuActionModel(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GotoMenuActionModel_C", "ExecuteUbergraph_BP_GotoMenuActionModel");

	Params::BP_GotoMenuActionModel_C_ExecuteUbergraph_BP_GotoMenuActionModel Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GotoMenuActionModel.BP_GotoMenuActionModel_C.OnClicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_GotoMenuActionModel_C::OnClicked(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GotoMenuActionModel_C", "OnClicked");

	Params::BP_GotoMenuActionModel_C_OnClicked Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}

}
