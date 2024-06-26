#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SmokeGenerator_Tracked

#include "Basic.hpp"

#include "SmokeGenerator_Tracked_classes.hpp"
#include "SmokeGenerator_Tracked_parameters.hpp"


namespace SDK
{

// Function SmokeGenerator_Tracked.SmokeGenerator_Tracked_C.ExecuteUbergraph_SmokeGenerator_Tracked
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ASmokeGenerator_Tracked_C::ExecuteUbergraph_SmokeGenerator_Tracked(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SmokeGenerator_Tracked_C", "ExecuteUbergraph_SmokeGenerator_Tracked");

	Params::SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SmokeGenerator_Tracked.SmokeGenerator_Tracked_C.ReceiveDestroyed
// (Event, Public, BlueprintEvent)

void ASmokeGenerator_Tracked_C::ReceiveDestroyed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SmokeGenerator_Tracked_C", "ReceiveDestroyed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SmokeGenerator_Tracked.SmokeGenerator_Tracked_C.SetupParticleSystem
// (Event, Protected, BlueprintEvent)
// Parameters:
// class AActor*                           OwnerActor                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ASmokeGenerator_Tracked_C::SetupParticleSystem(class AActor* OwnerActor)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SmokeGenerator_Tracked_C", "SetupParticleSystem");

	Params::SmokeGenerator_Tracked_C_SetupParticleSystem Parms{};

	Parms.OwnerActor = OwnerActor;

	UObject::ProcessEvent(Func, &Parms);
}

}

