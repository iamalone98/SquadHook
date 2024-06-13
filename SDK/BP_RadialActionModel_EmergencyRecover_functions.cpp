#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RadialActionModel_EmergencyRecover

#include "Basic.hpp"

#include "BP_RadialActionModel_EmergencyRecover_classes.hpp"
#include "BP_RadialActionModel_EmergencyRecover_parameters.hpp"


namespace SDK
{

// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_EmergencyRecover_C::ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover");

	Params::BP_RadialActionModel_EmergencyRecover_C_ExecuteUbergraph_BP_RadialActionModel_EmergencyRecover Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Cooldown Start
// (BlueprintCallable, BlueprintEvent)

void UBP_RadialActionModel_EmergencyRecover_C::Cooldown_Start()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "Cooldown Start");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.OnClicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_EmergencyRecover_C::OnClicked(class UBaseRadialMenu_C* Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "OnClicked");

	Params::BP_RadialActionModel_EmergencyRecover_C_OnClicked Parms{};

	Parms.Radial = Radial;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Cooldown Finished
// (BlueprintCallable, BlueprintEvent)

void UBP_RadialActionModel_EmergencyRecover_C::Cooldown_Finished()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "Cooldown Finished");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Populate
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRadialButton*                  Param_Widget                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBaseRadialMenu_C*                Menu                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UObject*                          Context                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_EmergencyRecover_C::Populate(class USQRadialButton* Param_Widget, class UBaseRadialMenu_C* Menu, class UObject* Context)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "Populate");

	Params::BP_RadialActionModel_EmergencyRecover_C_Populate Parms{};

	Parms.Param_Widget = Param_Widget;
	Parms.Menu = Menu;
	Parms.Context = Context;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Update Button
// (Private, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRadialButton*                  Param_Widget                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQVehicle*                       Param_Vehicle                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_RadialActionModel_EmergencyRecover_C::Update_Button(class USQRadialButton* Param_Widget, class ASQVehicle* Param_Vehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "Update Button");

	Params::BP_RadialActionModel_EmergencyRecover_C_Update_Button Parms{};

	Parms.Param_Widget = Param_Widget;
	Parms.Param_Vehicle = Param_Vehicle;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RadialActionModel_EmergencyRecover.BP_RadialActionModel_EmergencyRecover_C.Get Correct Recovery Methods
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQVehicle*                       Param_Vehicle                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// TSet<ESQVehicleRecoveryMethod>          RecoveryMethodsAvailable                               (Parm, OutParm)

void UBP_RadialActionModel_EmergencyRecover_C::Get_Correct_Recovery_Methods(class ASQVehicle* Param_Vehicle, TSet<ESQVehicleRecoveryMethod>* RecoveryMethodsAvailable) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RadialActionModel_EmergencyRecover_C", "Get Correct Recovery Methods");

	Params::BP_RadialActionModel_EmergencyRecover_C_Get_Correct_Recovery_Methods Parms{};

	Parms.Param_Vehicle = Param_Vehicle;

	UObject::ProcessEvent(Func, &Parms);

	if (RecoveryMethodsAvailable != nullptr)
		*RecoveryMethodsAvailable = std::move(Parms.RecoveryMethodsAvailable);
}

}

