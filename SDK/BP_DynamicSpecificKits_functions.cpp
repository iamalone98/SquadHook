#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_DynamicSpecificKits

#include "Basic.hpp"

#include "BP_DynamicSpecificKits_classes.hpp"
#include "BP_DynamicSpecificKits_parameters.hpp"


namespace SDK
{

// Function BP_DynamicSpecificKits.BP_DynamicSpecificKits_C.ExecuteUbergraph_BP_DynamicSpecificKits
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_DynamicSpecificKits_C::ExecuteUbergraph_BP_DynamicSpecificKits(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_DynamicSpecificKits_C", "ExecuteUbergraph_BP_DynamicSpecificKits");

	Params::BP_DynamicSpecificKits_C_ExecuteUbergraph_BP_DynamicSpecificKits Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_DynamicSpecificKits.BP_DynamicSpecificKits_C.Create Widgets
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Base_Radial                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_DynamicSpecificKits_C::Create_Widgets(class UBaseRadialMenu_C* Base_Radial)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_DynamicSpecificKits_C", "Create Widgets");

	Params::BP_DynamicSpecificKits_C_Create_Widgets Parms{};

	Parms.Base_Radial = Base_Radial;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_DynamicSpecificKits.BP_DynamicSpecificKits_C.ShouldUseRole
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UBP_SQRoleSettings_C*             In_Role                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Out_ShouldUse                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_DynamicSpecificKits_C::ShouldUseRole(class UBP_SQRoleSettings_C* In_Role, bool* Out_ShouldUse)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_DynamicSpecificKits_C", "ShouldUseRole");

	Params::BP_DynamicSpecificKits_C_ShouldUseRole Parms{};

	Parms.In_Role = In_Role;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_ShouldUse != nullptr)
		*Out_ShouldUse = Parms.Out_ShouldUse;
}

}
