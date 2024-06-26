#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Deployable_Hab

#include "Basic.hpp"

#include "BP_Deployable_Hab_classes.hpp"
#include "BP_Deployable_Hab_parameters.hpp"


namespace SDK
{

// Function BP_Deployable_Hab.BP_Deployable_Hab_C.ExecuteUbergraph_BP_Deployable_Hab
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::ExecuteUbergraph_BP_Deployable_Hab(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "ExecuteUbergraph_BP_Deployable_Hab");

	Params::BP_Deployable_Hab_C_ExecuteUbergraph_BP_Deployable_Hab Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.ReceiveTick
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   DeltaSeconds                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::ReceiveTick(float DeltaSeconds)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "ReceiveTick");

	Params::BP_Deployable_Hab_C_ReceiveTick Parms{};

	Parms.DeltaSeconds = DeltaSeconds;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.Placed
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::Placed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "Placed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.BPOnGhostMade
// (Event, Public, BlueprintEvent)

void ABP_Deployable_Hab_C::BPOnGhostMade()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "BPOnGhostMade");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.OnActivatingTimeStampChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQGameSpawn*                     SpawnPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::OnActivatingTimeStampChanged(class ASQGameSpawn* SpawnPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "OnActivatingTimeStampChanged");

	Params::BP_Deployable_Hab_C_OnActivatingTimeStampChanged Parms{};

	Parms.SpawnPoint = SpawnPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.OnPreSpawnPointEnabledChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQGameSpawn*                     SpawnPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::OnPreSpawnPointEnabledChanged(class ASQGameSpawn* SpawnPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "OnPreSpawnPointEnabledChanged");

	Params::BP_Deployable_Hab_C_OnPreSpawnPointEnabledChanged Parms{};

	Parms.SpawnPoint = SpawnPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.OnPreSpawnPointSiegeStateChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQGameSpawn*                     SpawnPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::OnPreSpawnPointSiegeStateChanged(class ASQGameSpawn* SpawnPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "OnPreSpawnPointSiegeStateChanged");

	Params::BP_Deployable_Hab_C_OnPreSpawnPointSiegeStateChanged Parms{};

	Parms.SpawnPoint = SpawnPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.ReceiveDestroyed
// (Event, Public, BlueprintEvent)

void ABP_Deployable_Hab_C::ReceiveDestroyed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "ReceiveDestroyed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.WaitConstruction
// (BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::WaitConstruction()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "WaitConstruction");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.BP_OnStateChange
// (Event, Public, BlueprintEvent)
// Parameters:
// ESQBuildState                           OldBuildState                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::BP_OnStateChange(ESQBuildState OldBuildState)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "BP_OnStateChange");

	Params::BP_Deployable_Hab_C_BP_OnStateChange Parms{};

	Parms.OldBuildState = OldBuildState;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_Deployable_Hab_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.OnRep_Spawnable
// (BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::OnRep_Spawnable()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "OnRep_Spawnable");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.Update TC Protection
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Gain_Protection                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_Deployable_Hab_C::Update_TC_Protection(bool Gain_Protection)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "Update TC Protection");

	Params::BP_Deployable_Hab_C_Update_TC_Protection Parms{};

	Parms.Gain_Protection = Gain_Protection;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.Update Commander Actions
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::Update_Commander_Actions()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "Update Commander Actions");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.SetActivateDelay
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   DelaySeconds                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Deployable_Hab_C::SetActivateDelay(float DelaySeconds)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "SetActivateDelay");

	Params::BP_Deployable_Hab_C_SetActivateDelay Parms{};

	Parms.DelaySeconds = DelaySeconds;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.DebugMessage
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::DebugMessage()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "DebugMessage");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.UpdateDoorwayMarkers
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void ABP_Deployable_Hab_C::UpdateDoorwayMarkers()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "UpdateDoorwayMarkers");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.Additional Can Capture
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Can_Capture                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_Deployable_Hab_C::Additional_Can_Capture(bool* Can_Capture)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "Additional Can Capture");

	Params::BP_Deployable_Hab_C_Additional_Can_Capture Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Can_Capture != nullptr)
		*Can_Capture = Parms.Can_Capture;
}


// Function BP_Deployable_Hab.BP_Deployable_Hab_C.GetGameSpawn
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQGameSpawn*                     ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class ASQGameSpawn* ABP_Deployable_Hab_C::GetGameSpawn()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Deployable_Hab_C", "GetGameSpawn");

	Params::BP_Deployable_Hab_C_GetGameSpawn Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

