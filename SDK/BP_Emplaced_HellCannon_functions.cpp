#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Emplaced_HellCannon

#include "Basic.hpp"

#include "BP_Emplaced_HellCannon_classes.hpp"
#include "BP_Emplaced_HellCannon_parameters.hpp"


namespace SDK
{

// Function BP_Emplaced_HellCannon.BP_Emplaced_HellCannon_C.ExecuteUbergraph_BP_Emplaced_HellCannon
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Emplaced_HellCannon_C::ExecuteUbergraph_BP_Emplaced_HellCannon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_HellCannon_C", "ExecuteUbergraph_BP_Emplaced_HellCannon");

	Params::BP_Emplaced_HellCannon_C_ExecuteUbergraph_BP_Emplaced_HellCannon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Emplaced_HellCannon.BP_Emplaced_HellCannon_C.BlueprintOnEquip
// (Event, Protected, BlueprintEvent)

void ABP_Emplaced_HellCannon_C::BlueprintOnEquip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_HellCannon_C", "BlueprintOnEquip");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Emplaced_HellCannon.BP_Emplaced_HellCannon_C.BlueprintOnFire
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          Origin                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Emplaced_HellCannon_C::BlueprintOnFire(const struct FVector& Origin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_HellCannon_C", "BlueprintOnFire");

	Params::BP_Emplaced_HellCannon_C_BlueprintOnFire Parms{};

	Parms.Origin = std::move(Origin);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Emplaced_HellCannon.BP_Emplaced_HellCannon_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_Emplaced_HellCannon_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_HellCannon_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}

}
