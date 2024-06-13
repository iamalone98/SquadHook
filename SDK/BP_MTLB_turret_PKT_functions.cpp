#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MTLB_turret_PKT

#include "Basic.hpp"

#include "BP_MTLB_turret_PKT_classes.hpp"
#include "BP_MTLB_turret_PKT_parameters.hpp"


namespace SDK
{

// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.ExecuteUbergraph_BP_MTLB_turret_PKT
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_MTLB_turret_PKT_C::ExecuteUbergraph_BP_MTLB_turret_PKT(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "ExecuteUbergraph_BP_MTLB_turret_PKT");

	Params::BP_MTLB_turret_PKT_C_ExecuteUbergraph_BP_MTLB_turret_PKT Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.BP_OnVehicleZoom
// (Event, Protected, BlueprintEvent)

void ABP_MTLB_turret_PKT_C::BP_OnVehicleZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "BP_OnVehicleZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.ResetZoom
// (Event, Protected, BlueprintCallable, BlueprintEvent)

void ABP_MTLB_turret_PKT_C::ResetZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "ResetZoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_MTLB_turret_PKT_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.InpActEvt_Fire_K2Node_InputActionEvent_0
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_MTLB_turret_PKT_C::InpActEvt_Fire_K2Node_InputActionEvent_0(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "InpActEvt_Fire_K2Node_InputActionEvent_0");

	Params::BP_MTLB_turret_PKT_C_InpActEvt_Fire_K2Node_InputActionEvent_0 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.InpActEvt_Fire_K2Node_InputActionEvent_1
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_MTLB_turret_PKT_C::InpActEvt_Fire_K2Node_InputActionEvent_1(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "InpActEvt_Fire_K2Node_InputActionEvent_1");

	Params::BP_MTLB_turret_PKT_C_InpActEvt_Fire_K2Node_InputActionEvent_1 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.Timeline_0__UpdateFunc
// (BlueprintEvent)

void ABP_MTLB_turret_PKT_C::Timeline_0__UpdateFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "Timeline_0__UpdateFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.Timeline_0__FinishedFunc
// (BlueprintEvent)

void ABP_MTLB_turret_PKT_C::Timeline_0__FinishedFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "Timeline_0__FinishedFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_MTLB_turret_PKT_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.Get3PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_MTLB_turret_PKT_C::Get3PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "Get3PAttachComponent");

	Params::BP_MTLB_turret_PKT_C_Get3PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.Get1PAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_MTLB_turret_PKT_C::Get1PAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "Get1PAttachComponent");

	Params::BP_MTLB_turret_PKT_C_Get1PAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.GetMasterPoseComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USkinnedMeshComponent*            ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USkinnedMeshComponent* ABP_MTLB_turret_PKT_C::GetMasterPoseComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "GetMasterPoseComponent");

	Params::BP_MTLB_turret_PKT_C_GetMasterPoseComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MTLB_turret_PKT.BP_MTLB_turret_PKT_C.GetWeaponAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_MTLB_turret_PKT_C::GetWeaponAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MTLB_turret_PKT_C", "GetWeaponAttachComponent");

	Params::BP_MTLB_turret_PKT_C_GetWeaponAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
