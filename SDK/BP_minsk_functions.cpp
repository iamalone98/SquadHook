#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_minsk

#include "Basic.hpp"

#include "BP_minsk_classes.hpp"
#include "BP_minsk_parameters.hpp"


namespace SDK
{

// Function BP_minsk.BP_minsk_C.ExecuteUbergraph_BP_minsk
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_minsk_C::ExecuteUbergraph_BP_minsk(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_minsk_C", "ExecuteUbergraph_BP_minsk");

	Params::BP_minsk_C_ExecuteUbergraph_BP_minsk Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_minsk.BP_minsk_C.DrivetrainComponentRepaired
// (Event, Public, BlueprintEvent)
// Parameters:
// class USQDriveTrainComponent*           DriveTrainComponent                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_minsk_C::DrivetrainComponentRepaired(class USQDriveTrainComponent* DriveTrainComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_minsk_C", "DrivetrainComponentRepaired");

	Params::BP_minsk_C_DrivetrainComponentRepaired Parms{};

	Parms.DriveTrainComponent = DriveTrainComponent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_minsk.BP_minsk_C.DrivetrainComponentDestroyed
// (Event, Public, BlueprintEvent)
// Parameters:
// class USQDriveTrainComponent*           DriveTrainComponent                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_minsk_C::DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_minsk_C", "DrivetrainComponentDestroyed");

	Params::BP_minsk_C_DrivetrainComponentDestroyed Parms{};

	Parms.DriveTrainComponent = DriveTrainComponent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_minsk.BP_minsk_C.UpdateDamageWheelVisual
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             Bone                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Destroyed                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class USQVehicleWheel*                  Wheel                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Do_Effects                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_minsk_C::UpdateDamageWheelVisual(class FName Bone, bool Destroyed, class USQVehicleWheel* Wheel, bool Do_Effects)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_minsk_C", "UpdateDamageWheelVisual");

	Params::BP_minsk_C_UpdateDamageWheelVisual Parms{};

	Parms.Bone = Bone;
	Parms.Destroyed = Destroyed;
	Parms.Wheel = Wheel;
	Parms.Do_Effects = Do_Effects;

	UObject::ProcessEvent(Func, &Parms);
}

}

