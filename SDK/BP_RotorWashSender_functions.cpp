#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RotorWashSender

#include "Basic.hpp"

#include "BP_RotorWashSender_classes.hpp"
#include "BP_RotorWashSender_parameters.hpp"


namespace SDK
{

// Function BP_RotorWashSender.BP_RotorWashSender_C.ExecuteUbergraph_BP_RotorWashSender
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RotorWashSender_C::ExecuteUbergraph_BP_RotorWashSender(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RotorWashSender_C", "ExecuteUbergraph_BP_RotorWashSender");

	Params::BP_RotorWashSender_C_ExecuteUbergraph_BP_RotorWashSender Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RotorWashSender.BP_RotorWashSender_C.Initialize
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_RotorWashSender_C::Initialize()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RotorWashSender_C", "Initialize");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_RotorWashSender.BP_RotorWashSender_C.SetCanUpdate
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    CanUpdate                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_RotorWashSender_C::SetCanUpdate(bool CanUpdate)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RotorWashSender_C", "SetCanUpdate");

	Params::BP_RotorWashSender_C_SetCanUpdate Parms{};

	Parms.CanUpdate = CanUpdate;

	UObject::ProcessEvent(Func, &Parms);
}

}

