#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV510UA

#include "Basic.hpp"

#include "BP_FV510UA_classes.hpp"
#include "BP_FV510UA_parameters.hpp"


namespace SDK
{

// Function BP_FV510UA.BP_FV510UA_C.ExecuteUbergraph_BP_FV510UA
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV510UA_C::ExecuteUbergraph_BP_FV510UA(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510UA_C", "ExecuteUbergraph_BP_FV510UA");

	Params::BP_FV510UA_C_ExecuteUbergraph_BP_FV510UA Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510UA.BP_FV510UA_C.DrivetrainComponentRepaired
// (Event, Public, BlueprintEvent)
// Parameters:
// class USQDriveTrainComponent*           DriveTrainComponent                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV510UA_C::DrivetrainComponentRepaired(class USQDriveTrainComponent* DriveTrainComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510UA_C", "DrivetrainComponentRepaired");

	Params::BP_FV510UA_C_DrivetrainComponentRepaired Parms{};

	Parms.DriveTrainComponent = DriveTrainComponent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510UA.BP_FV510UA_C.DrivetrainComponentDestroyed
// (Event, Public, BlueprintEvent)
// Parameters:
// class USQDriveTrainComponent*           DriveTrainComponent                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV510UA_C::DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510UA_C", "DrivetrainComponentDestroyed");

	Params::BP_FV510UA_C_DrivetrainComponentDestroyed Parms{};

	Parms.DriveTrainComponent = DriveTrainComponent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510UA.BP_FV510UA_C.Update Damaged Track Visual - FV510UA
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UObject*                          VehicleTrack                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    bIsTrackDestroyed                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    ShowOriginalTrack                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_FV510UA_C::Update_Damaged_Track_Visual_Minus_FV510UA(class UObject* VehicleTrack, bool bIsTrackDestroyed, bool ShowOriginalTrack)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510UA_C", "Update Damaged Track Visual - FV510UA");

	Params::BP_FV510UA_C_Update_Damaged_Track_Visual_Minus_FV510UA Parms{};

	Parms.VehicleTrack = VehicleTrack;
	Parms.bIsTrackDestroyed = bIsTrackDestroyed;
	Parms.ShowOriginalTrack = ShowOriginalTrack;

	UObject::ProcessEvent(Func, &Parms);
}

}
