#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialActionModel_ControlSupplies

#include "Basic.hpp"

#include "BP_RadialActionModel_ControlSupplies_classes.hpp"
#include "BP_RadialActionModel_ControlSupplies_parameters.hpp"


namespace SDK
{

// Function BP_RadialActionModel_ControlSupplies.BP_RadialActionModel_ControlSupplies_C.ExecuteUbergraph_BP_RadialActionModel_ControlSupplies
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_ControlSupplies_C::ExecuteUbergraph_BP_RadialActionModel_ControlSupplies(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_ControlSupplies_C", "ExecuteUbergraph_BP_RadialActionModel_ControlSupplies");

	Params::BP_RadialActionModel_ControlSupplies_C_ExecuteUbergraph_BP_RadialActionModel_ControlSupplies Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_ControlSupplies.BP_RadialActionModel_ControlSupplies_C.OnReleased
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_ControlSupplies_C::OnReleased(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_ControlSupplies_C", "OnReleased");

	Params::BP_RadialActionModel_ControlSupplies_C_OnReleased Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_ControlSupplies.BP_RadialActionModel_ControlSupplies_C.OnClicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_ControlSupplies_C::OnClicked(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_ControlSupplies_C", "OnClicked");

	Params::BP_RadialActionModel_ControlSupplies_C_OnClicked Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_ControlSupplies.BP_RadialActionModel_ControlSupplies_C.Validate Logistics
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Is_Valid                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_RadialActionModel_ControlSupplies_C::Validate_Logistics(class UBaseRadialMenu_C* Radial, bool* Is_Valid)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_ControlSupplies_C", "Validate Logistics");

	Params::BP_RadialActionModel_ControlSupplies_C_Validate_Logistics Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);

	if (Is_Valid != nullptr)
		*Is_Valid = Parms.Is_Valid;
}


// Function BP_RadialActionModel_ControlSupplies.BP_RadialActionModel_ControlSupplies_C.Is Soldier Alive
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class AController*                      Target                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Alive                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_RadialActionModel_ControlSupplies_C::Is_Soldier_Alive(class AController* Target, bool* Alive)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_ControlSupplies_C", "Is Soldier Alive");

	Params::BP_RadialActionModel_ControlSupplies_C_Is_Soldier_Alive Parms{};

	Parms.Target = Target;

	UObject::ProcessEvent(Func, &Parms);

	if (Alive != nullptr)
		*Alive = Parms.Alive;
}

}

