#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV4034_Turret

#include "Basic.hpp"

#include "BP_FV4034_Turret_classes.hpp"
#include "BP_FV4034_Turret_parameters.hpp"


namespace SDK
{

// Function BP_FV4034_Turret.BP_FV4034_Turret_C.ExecuteUbergraph_BP_FV4034_Turret
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV4034_Turret_C::ExecuteUbergraph_BP_FV4034_Turret(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV4034_Turret_C", "ExecuteUbergraph_BP_FV4034_Turret");

	Params::BP_FV4034_Turret_C_ExecuteUbergraph_BP_FV4034_Turret Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV4034_Turret.BP_FV4034_Turret_C.ServerSetStabilizationHeading
// (Net, NetServer, BlueprintCallable, BlueprintEvent)

void ABP_FV4034_Turret_C::ServerSetStabilizationHeading()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV4034_Turret_C", "ServerSetStabilizationHeading");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV4034_Turret.BP_FV4034_Turret_C.InpActEvt_DesignateTarget_K2Node_InputActionEvent_0
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_FV4034_Turret_C::InpActEvt_DesignateTarget_K2Node_InputActionEvent_0(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV4034_Turret_C", "InpActEvt_DesignateTarget_K2Node_InputActionEvent_0");

	Params::BP_FV4034_Turret_C_InpActEvt_DesignateTarget_K2Node_InputActionEvent_0 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}

}

