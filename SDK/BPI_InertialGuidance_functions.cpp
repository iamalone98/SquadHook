#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPI_InertialGuidance

#include "Basic.hpp"

#include "BPI_InertialGuidance_classes.hpp"
#include "BPI_InertialGuidance_parameters.hpp"


namespace SDK
{

// Function BPI_InertialGuidance.BPI_InertialGuidance_C.GetTargetAngularSpeedDegrees
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Target_Angular_Speed                                   (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void IBPI_InertialGuidance_C::GetTargetAngularSpeedDegrees(float* Target_Angular_Speed)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPI_InertialGuidance_C", "GetTargetAngularSpeedDegrees");

	Params::BPI_InertialGuidance_C_GetTargetAngularSpeedDegrees Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Target_Angular_Speed != nullptr)
		*Target_Angular_Speed = Parms.Target_Angular_Speed;
}


// Function BPI_InertialGuidance.BPI_InertialGuidance_C.GetGuidanceEnabled
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    bEnabled                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void IBPI_InertialGuidance_C::GetGuidanceEnabled(bool* bEnabled)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPI_InertialGuidance_C", "GetGuidanceEnabled");

	Params::BPI_InertialGuidance_C_GetGuidanceEnabled Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (bEnabled != nullptr)
		*bEnabled = Parms.bEnabled;
}

}

