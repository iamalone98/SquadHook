#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_CommandMaster

#include "Basic.hpp"

#include "BP_MapMarker_CommandMaster_classes.hpp"
#include "BP_MapMarker_CommandMaster_parameters.hpp"


namespace SDK
{

// Function BP_MapMarker_CommandMaster.BP_MapMarker_CommandMaster_C.ExecuteUbergraph_BP_MapMarker_CommandMaster
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_MapMarker_CommandMaster_C::ExecuteUbergraph_BP_MapMarker_CommandMaster(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_CommandMaster_C", "ExecuteUbergraph_BP_MapMarker_CommandMaster");

	Params::BP_MapMarker_CommandMaster_C_ExecuteUbergraph_BP_MapMarker_CommandMaster Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapMarker_CommandMaster.BP_MapMarker_CommandMaster_C.OnDestroyed_Event_0
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class AActor*                           DestroyedActor                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_MapMarker_CommandMaster_C::OnDestroyed_Event_0(class AActor* DestroyedActor)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_CommandMaster_C", "OnDestroyed_Event_0");

	Params::BP_MapMarker_CommandMaster_C_OnDestroyed_Event_0 Parms{};

	Parms.DestroyedActor = DestroyedActor;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapMarker_CommandMaster.BP_MapMarker_CommandMaster_C.Bind To Destroy
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class AActor*                           Bind_To                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_MapMarker_CommandMaster_C::Bind_To_Destroy(class AActor* Bind_To)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_CommandMaster_C", "Bind To Destroy");

	Params::BP_MapMarker_CommandMaster_C_Bind_To_Destroy Parms{};

	Parms.Bind_To = Bind_To;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapMarker_CommandMaster.BP_MapMarker_CommandMaster_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_MapMarker_CommandMaster_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapMarker_CommandMaster_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}

