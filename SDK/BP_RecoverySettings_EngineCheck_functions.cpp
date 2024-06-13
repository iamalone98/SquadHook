#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RecoverySettings_EngineCheck

#include "Basic.hpp"

#include "BP_RecoverySettings_EngineCheck_classes.hpp"
#include "BP_RecoverySettings_EngineCheck_parameters.hpp"


namespace SDK
{

// Function BP_RecoverySettings_EngineCheck.BP_RecoverySettings_EngineCheck_C.CanUseEmergencyRecovery
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USQVehicleEmergencyRecoveryComponent*RecoveryComponent                                      (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// ESQVehicleRecoveryMethod                RecoveryMethod                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_RecoverySettings_EngineCheck_C::CanUseEmergencyRecovery(const class USQVehicleEmergencyRecoveryComponent* RecoveryComponent, ESQVehicleRecoveryMethod RecoveryMethod) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RecoverySettings_EngineCheck_C", "CanUseEmergencyRecovery");

	Params::BP_RecoverySettings_EngineCheck_C_CanUseEmergencyRecovery Parms{};

	Parms.RecoveryComponent = RecoveryComponent;
	Parms.RecoveryMethod = RecoveryMethod;

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
