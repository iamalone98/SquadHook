#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ChangeRoleActionx

#include "Basic.hpp"

#include "BP_ChangeRoleActionx_classes.hpp"
#include "BP_ChangeRoleActionx_parameters.hpp"


namespace SDK
{

// Function BP_ChangeRoleActionx.BP_ChangeRoleActionx_C.ExecuteUbergraph_BP_ChangeRoleActionx
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_ChangeRoleActionx_C::ExecuteUbergraph_BP_ChangeRoleActionx(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ChangeRoleActionx_C", "ExecuteUbergraph_BP_ChangeRoleActionx");

	Params::BP_ChangeRoleActionx_C_ExecuteUbergraph_BP_ChangeRoleActionx Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ChangeRoleActionx.BP_ChangeRoleActionx_C.ChangeRole
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBaseRadialMenu_C*                Radial                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQRoleSettings*                  Role                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_ChangeRoleActionx_C::ChangeRole(class UBaseRadialMenu_C* Radial, class USQRoleSettings* Role)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ChangeRoleActionx_C", "ChangeRole");

	Params::BP_ChangeRoleActionx_C_ChangeRole Parms{};

	Parms.Radial = Radial;
	Parms.Role = Role;

	UObject::ProcessEvent(Func, &Parms);
}

}

