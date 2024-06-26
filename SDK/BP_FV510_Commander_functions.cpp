#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV510_Commander

#include "Basic.hpp"

#include "BP_FV510_Commander_classes.hpp"
#include "BP_FV510_Commander_parameters.hpp"


namespace SDK
{

// Function BP_FV510_Commander.BP_FV510_Commander_C.ExecuteUbergraph_BP_FV510_Commander
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV510_Commander_C::ExecuteUbergraph_BP_FV510_Commander(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "ExecuteUbergraph_BP_FV510_Commander");

	Params::BP_FV510_Commander_C_ExecuteUbergraph_BP_FV510_Commander Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.BP_OnVehicleZoom
// (Event, Protected, BlueprintEvent)

void ABP_FV510_Commander_C::BP_OnVehicleZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "BP_OnVehicleZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.ResetZoom
// (Event, Protected, BlueprintCallable, BlueprintEvent)

void ABP_FV510_Commander_C::ResetZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "ResetZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_FV510_Commander_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.Timeline_0__UpdateFunc
// (BlueprintEvent)

void ABP_FV510_Commander_C::Timeline_0__UpdateFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "Timeline_0__UpdateFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.Timeline_0__FinishedFunc
// (BlueprintEvent)

void ABP_FV510_Commander_C::Timeline_0__FinishedFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "Timeline_0__FinishedFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_FV510_Commander_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.GetWeaponAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Commander_C::GetWeaponAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "GetWeaponAttachComponent");

	Params::BP_FV510_Commander_C_GetWeaponAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.Get3PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Commander_C::Get3PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "Get3PAttachComponent");

	Params::BP_FV510_Commander_C_Get3PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.Get1PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Commander_C::Get1PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "Get1PAttachComponent");

	Params::BP_FV510_Commander_C_Get1PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.GetMasterPoseComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USkinnedMeshComponent*            ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USkinnedMeshComponent* ABP_FV510_Commander_C::GetMasterPoseComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "GetMasterPoseComponent");

	Params::BP_FV510_Commander_C_GetMasterPoseComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.GetTurretMovementComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USQTurretMovementComponent*       ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USQTurretMovementComponent* ABP_FV510_Commander_C::GetTurretMovementComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "GetTurretMovementComponent");

	Params::BP_FV510_Commander_C_GetTurretMovementComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.GetADSCameraLocationComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Commander_C::GetADSCameraLocationComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "GetADSCameraLocationComponent");

	Params::BP_FV510_Commander_C_GetADSCameraLocationComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Commander.BP_FV510_Commander_C.GetSoldierAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Commander_C::GetSoldierAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Commander_C", "GetSoldierAttachComponent");

	Params::BP_FV510_Commander_C_GetSoldierAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

