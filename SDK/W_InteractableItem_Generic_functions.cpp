#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableItem_Generic

#include "Basic.hpp"

#include "W_InteractableItem_Generic_classes.hpp"
#include "W_InteractableItem_Generic_parameters.hpp"


namespace SDK
{

// Function W_InteractableItem_Generic.W_InteractableItem_Generic_C.Get Format Box
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UHorizontalBox*                   Param_FormatBox                                        (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableItem_Generic_C::Get_Format_Box(class UHorizontalBox** Param_FormatBox)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableItem_Generic_C", "Get Format Box");

	Params::W_InteractableItem_Generic_C_Get_Format_Box Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_FormatBox != nullptr)
		*Param_FormatBox = Parms.Param_FormatBox;
}

}

