#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV510_Turret

#include "Basic.hpp"

#include "BP_FV510_Turret_classes.hpp"
#include "BP_FV510_Turret_parameters.hpp"


namespace SDK
{

// Function BP_FV510_Turret.BP_FV510_Turret_C.ExecuteUbergraph_BP_FV510_Turret
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_FV510_Turret_C::ExecuteUbergraph_BP_FV510_Turret(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "ExecuteUbergraph_BP_FV510_Turret");

	Params::BP_FV510_Turret_C_ExecuteUbergraph_BP_FV510_Turret Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.BP_OnVehicleZoom
// (Event, Protected, BlueprintEvent)

void ABP_FV510_Turret_C::BP_OnVehicleZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "BP_OnVehicleZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.ResetZoom
// (Event, Protected, BlueprintCallable, BlueprintEvent)

void ABP_FV510_Turret_C::ResetZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "ResetZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_FV510_Turret_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.InpActEvt_Fire_K2Node_InputActionEvent_0
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_FV510_Turret_C::InpActEvt_Fire_K2Node_InputActionEvent_0(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "InpActEvt_Fire_K2Node_InputActionEvent_0");

	Params::BP_FV510_Turret_C_InpActEvt_Fire_K2Node_InputActionEvent_0 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.InpActEvt_Fire_K2Node_InputActionEvent_1
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_FV510_Turret_C::InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "InpActEvt_Fire_K2Node_InputActionEvent_1");

	Params::BP_FV510_Turret_C_InpActEvt_Fire_K2Node_InputActionEvent_1 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.Timeline_0__UpdateFunc
// (BlueprintEvent)

void ABP_FV510_Turret_C::Timeline_0__UpdateFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "Timeline_0__UpdateFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.Timeline_0__FinishedFunc
// (BlueprintEvent)

void ABP_FV510_Turret_C::Timeline_0__FinishedFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "Timeline_0__FinishedFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_FV510_Turret_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.GetWeaponAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Turret_C::GetWeaponAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "GetWeaponAttachComponent");

	Params::BP_FV510_Turret_C_GetWeaponAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.Get3PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Turret_C::Get3PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "Get3PAttachComponent");

	Params::BP_FV510_Turret_C_Get3PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.Get1PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Turret_C::Get1PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "Get1PAttachComponent");

	Params::BP_FV510_Turret_C_Get1PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.GetMasterPoseComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USkinnedMeshComponent*            ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USkinnedMeshComponent* ABP_FV510_Turret_C::GetMasterPoseComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "GetMasterPoseComponent");

	Params::BP_FV510_Turret_C_GetMasterPoseComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.GetSoldierAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Turret_C::GetSoldierAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "GetSoldierAttachComponent");

	Params::BP_FV510_Turret_C_GetSoldierAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.GetADSCameraLocationComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_FV510_Turret_C::GetADSCameraLocationComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "GetADSCameraLocationComponent");

	Params::BP_FV510_Turret_C_GetADSCameraLocationComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_FV510_Turret.BP_FV510_Turret_C.GetTurretMovementComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USQTurretMovementComponent*       ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USQTurretMovementComponent* ABP_FV510_Turret_C::GetTurretMovementComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_FV510_Turret_C", "GetTurretMovementComponent");

	Params::BP_FV510_Turret_C_GetTurretMovementComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

