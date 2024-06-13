#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericShovel

#include "Basic.hpp"

#include "BP_GenericShovel_classes.hpp"
#include "BP_GenericShovel_parameters.hpp"


namespace SDK
{

// Function BP_GenericShovel.BP_GenericShovel_C.ExecuteUbergraph_BP_GenericShovel
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericShovel_C::ExecuteUbergraph_BP_GenericShovel(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "ExecuteUbergraph_BP_GenericShovel");

	Params::BP_GenericShovel_C_ExecuteUbergraph_BP_GenericShovel Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericShovel.BP_GenericShovel_C.Event Destroy
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Destroying                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericShovel_C::Event_Destroy(bool Destroying)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "Event Destroy");

	Params::BP_GenericShovel_C_Event_Destroy Parms{};

	Parms.Destroying = Destroying;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericShovel.BP_GenericShovel_C.Event Dig
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Digging                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericShovel_C::Event_Dig(bool Digging)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "Event Dig");

	Params::BP_GenericShovel_C_Event_Dig Parms{};

	Parms.Digging = Digging;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericShovel.BP_GenericShovel_C.MovementWasBlocked
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::MovementWasBlocked()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "MovementWasBlocked");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.ServerStopBuilding
// (Net, NetReliable, NetServer, BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::ServerStopBuilding()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "ServerStopBuilding");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.ServerStartBuilding
// (Net, NetReliable, NetServer, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    IsConstructing                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericShovel_C::ServerStartBuilding(bool IsConstructing)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "ServerStartBuilding");

	Params::BP_GenericShovel_C_ServerStartBuilding Parms{};

	Parms.IsConstructing = IsConstructing;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericShovel.BP_GenericShovel_C.BlueprintOnUnequip
// (Event, Protected, BlueprintEvent)

void ABP_GenericShovel_C::BlueprintOnUnequip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "BlueprintOnUnequip");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.BPEndAltUse
// (Event, Public, BlueprintEvent)

void ABP_GenericShovel_C::BPEndAltUse()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "BPEndAltUse");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.BPBeginAltUse
// (Event, Public, BlueprintEvent)

void ABP_GenericShovel_C::BPBeginAltUse()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "BPBeginAltUse");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.BPEndUse
// (Event, Public, BlueprintEvent)

void ABP_GenericShovel_C::BPEndUse()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "BPEndUse");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.BPBeginUse
// (Event, Public, BlueprintEvent)

void ABP_GenericShovel_C::BPBeginUse()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "BPBeginUse");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.ApplyHealth
// (Net, NetReliable, NetServer, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQDeployable*                    DeployableToBuild                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   HealAmount                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericShovel_C::ApplyHealth(class ASQDeployable* DeployableToBuild, float HealAmount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "ApplyHealth");

	Params::BP_GenericShovel_C_ApplyHealth Parms{};

	Parms.DeployableToBuild = DeployableToBuild;
	Parms.HealAmount = HealAmount;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericShovel.BP_GenericShovel_C.HitDeployable
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::HitDeployable()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "HitDeployable");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.MovementBlock
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    AllowHit                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericShovel_C::MovementBlock(bool* AllowHit)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "MovementBlock");

	Params::BP_GenericShovel_C_MovementBlock Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (AllowHit != nullptr)
		*AllowHit = Parms.AllowHit;
}


// Function BP_GenericShovel.BP_GenericShovel_C.TryShovel
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQDeployable*                    Deployable                                             (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericShovel_C::TryShovel(class ASQDeployable** Deployable)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "TryShovel");

	Params::BP_GenericShovel_C_TryShovel Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Deployable != nullptr)
		*Deployable = Parms.Deployable;
}


// Function BP_GenericShovel.BP_GenericShovel_C.CleanUpBuildingState
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::CleanUpBuildingState()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "CleanUpBuildingState");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.OnRep_IsBuilding
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::OnRep_IsBuilding()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "OnRep_IsBuilding");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericShovel.BP_GenericShovel_C.OnRep_IsDestroying
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericShovel_C::OnRep_IsDestroying()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericShovel_C", "OnRep_IsDestroying");

	UObject::ProcessEvent(Func, nullptr);
}

}
