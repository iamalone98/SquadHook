#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericVehicleOpenTurretWeapon

#include "Basic.hpp"

#include "BP_GenericVehicleOpenTurretWeapon_classes.hpp"
#include "BP_GenericVehicleOpenTurretWeapon_parameters.hpp"


namespace SDK
{

// Function BP_GenericVehicleOpenTurretWeapon.BP_GenericVehicleOpenTurretWeapon_C.ExecuteUbergraph_BP_GenericVehicleOpenTurretWeapon
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericVehicleOpenTurretWeapon_C::ExecuteUbergraph_BP_GenericVehicleOpenTurretWeapon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericVehicleOpenTurretWeapon_C", "ExecuteUbergraph_BP_GenericVehicleOpenTurretWeapon");

	Params::BP_GenericVehicleOpenTurretWeapon_C_ExecuteUbergraph_BP_GenericVehicleOpenTurretWeapon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericVehicleOpenTurretWeapon.BP_GenericVehicleOpenTurretWeapon_C.SoldierEntersVehicle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericVehicleOpenTurretWeapon_C::SoldierEntersVehicle(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericVehicleOpenTurretWeapon_C", "SoldierEntersVehicle");

	Params::BP_GenericVehicleOpenTurretWeapon_C_SoldierEntersVehicle Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericVehicleOpenTurretWeapon.BP_GenericVehicleOpenTurretWeapon_C.CameraOnWeapon
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericVehicleOpenTurretWeapon_C::CameraOnWeapon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericVehicleOpenTurretWeapon_C", "CameraOnWeapon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericVehicleOpenTurretWeapon.BP_GenericVehicleOpenTurretWeapon_C.CameraOnSoldier
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericVehicleOpenTurretWeapon_C::CameraOnSoldier()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericVehicleOpenTurretWeapon_C", "CameraOnSoldier");

	UObject::ProcessEvent(Func, nullptr);
}

}
