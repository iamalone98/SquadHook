#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon

#include "Basic.hpp"

#include "BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_classes.hpp"
#include "BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_parameters.hpp"


namespace SDK
{

// Function BP_Emplaced_ZU23-2_Antiaircannon_Weapon.BP_Emplaced_ZU23-2_Antiaircannon_Weapon_C.ExecuteUbergraph_BP_Emplaced_ZU23-2_Antiaircannon_Weapon
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_C::ExecuteUbergraph_BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_ZU23-2_Antiaircannon_Weapon_C", "ExecuteUbergraph_BP_Emplaced_ZU23-2_Antiaircannon_Weapon");

	Params::BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_C_ExecuteUbergraph_BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Emplaced_ZU23-2_Antiaircannon_Weapon.BP_Emplaced_ZU23-2_Antiaircannon_Weapon_C.BlueprintOnFire
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          Origin                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_C::BlueprintOnFire(const struct FVector& Origin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Emplaced_ZU23-2_Antiaircannon_Weapon_C", "BlueprintOnFire");

	Params::BP_Emplaced_ZU23Minus2_Antiaircannon_Weapon_C_BlueprintOnFire Parms{};

	Parms.Origin = std::move(Origin);

	UObject::ProcessEvent(Func, &Parms);
}

}

