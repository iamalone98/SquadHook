#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnableDeployableItem

#include "Basic.hpp"

#include "BP_SpawnableDeployableItem_classes.hpp"
#include "BP_SpawnableDeployableItem_parameters.hpp"


namespace SDK
{

// Function BP_SpawnableDeployableItem.BP_SpawnableDeployableItem_C.Setup
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UObject*                          Data                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class FText                             FailReason                                             (Parm, OutParm)

void UBP_SpawnableDeployableItem_C::Setup(class UObject* Data, bool* Success, class FText* FailReason)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SpawnableDeployableItem_C", "Setup");

	Params::BP_SpawnableDeployableItem_C_Setup Parms{};

	Parms.Data = Data;

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (FailReason != nullptr)
		*FailReason = std::move(Parms.FailReason);
}

}
