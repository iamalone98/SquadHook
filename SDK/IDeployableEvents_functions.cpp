#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IDeployableEvents

#include "Basic.hpp"

#include "IDeployableEvents_classes.hpp"
#include "IDeployableEvents_parameters.hpp"


namespace SDK
{

// Function IDeployableEvents.IDeployableEvents_C.OnServerValidatedItemPlacement
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQDeployableItem*                Deployable                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void IIDeployableEvents_C::OnServerValidatedItemPlacement(class ASQDeployableItem* Deployable)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IDeployableEvents_C", "OnServerValidatedItemPlacement");

	Params::IDeployableEvents_C_OnServerValidatedItemPlacement Parms{};

	Parms.Deployable = Deployable;

	UObject::ProcessEvent(Func, &Parms);
}


// Function IDeployableEvents.IDeployableEvents_C.OnClientInvalidatedItemPlacement
// (Public, BlueprintCallable, BlueprintEvent)

void IIDeployableEvents_C::OnClientInvalidatedItemPlacement()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("IDeployableEvents_C", "OnClientInvalidatedItemPlacement");

	UObject::ProcessEvent(Func, nullptr);
}

}
