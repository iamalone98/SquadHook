#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Crewman_Kits

#include "Basic.hpp"

#include "BP_Crewman_Kits_classes.hpp"
#include "BP_Crewman_Kits_parameters.hpp"


namespace SDK
{

// Function BP_Crewman_Kits.BP_Crewman_Kits_C.ExecuteUbergraph_BP_Crewman_Kits
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_Crewman_Kits_C::ExecuteUbergraph_BP_Crewman_Kits(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Crewman_Kits_C", "ExecuteUbergraph_BP_Crewman_Kits");

	Params::BP_Crewman_Kits_C_ExecuteUbergraph_BP_Crewman_Kits Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Crewman_Kits.BP_Crewman_Kits_C.CreateChildWidgets
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                BaseRadialMenu                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_Crewman_Kits_C::CreateChildWidgets(class UBaseRadialMenu_C* BaseRadialMenu)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Crewman_Kits_C", "CreateChildWidgets");

	Params::BP_Crewman_Kits_C_CreateChildWidgets Parms{};

	Parms.BaseRadialMenu = BaseRadialMenu;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Crewman_Kits.BP_Crewman_Kits_C.ShouldUseRole
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UBP_SQRoleSettings_C*             In_Role                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Out_ShouldUse                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_Crewman_Kits_C::ShouldUseRole(class UBP_SQRoleSettings_C* In_Role, bool* Out_ShouldUse)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Crewman_Kits_C", "ShouldUseRole");

	Params::BP_Crewman_Kits_C_ShouldUseRole Parms{};

	Parms.In_Role = In_Role;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_ShouldUse != nullptr)
		*Out_ShouldUse = Parms.Out_ShouldUse;
}

}
