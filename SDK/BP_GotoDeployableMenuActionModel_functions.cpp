#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GotoDeployableMenuActionModel

#include "Basic.hpp"

#include "BP_GotoDeployableMenuActionModel_classes.hpp"
#include "BP_GotoDeployableMenuActionModel_parameters.hpp"


namespace SDK
{

// Function BP_GotoDeployableMenuActionModel.BP_GotoDeployableMenuActionModel_C.ExecuteUbergraph_BP_GotoDeployableMenuActionModel
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_GotoDeployableMenuActionModel_C::ExecuteUbergraph_BP_GotoDeployableMenuActionModel(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GotoDeployableMenuActionModel_C", "ExecuteUbergraph_BP_GotoDeployableMenuActionModel");

	Params::BP_GotoDeployableMenuActionModel_C_ExecuteUbergraph_BP_GotoDeployableMenuActionModel Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GotoDeployableMenuActionModel.BP_GotoDeployableMenuActionModel_C.OnClicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_GotoDeployableMenuActionModel_C::OnClicked(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GotoDeployableMenuActionModel_C", "OnClicked");

	Params::BP_GotoDeployableMenuActionModel_C_OnClicked Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}

}

