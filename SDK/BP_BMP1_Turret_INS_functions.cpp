#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BMP1_Turret_INS

#include "Basic.hpp"

#include "BP_BMP1_Turret_INS_classes.hpp"
#include "BP_BMP1_Turret_INS_parameters.hpp"


namespace SDK
{

// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.ExecuteUbergraph_BP_BMP1_Turret_INS
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_BMP1_Turret_INS_C::ExecuteUbergraph_BP_BMP1_Turret_INS(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BMP1_Turret_INS_C", "ExecuteUbergraph_BP_BMP1_Turret_INS");

	Params::BP_BMP1_Turret_INS_C_ExecuteUbergraph_BP_BMP1_Turret_INS Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.AT3_OnFire
// (Net, NetMulticast, BlueprintCallable, BlueprintEvent)

void ABP_BMP1_Turret_INS_C::AT3_OnFire()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BMP1_Turret_INS_C", "AT3_OnFire");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.AT3_OnReloaded
// (Net, NetMulticast, BlueprintCallable, BlueprintEvent)

void ABP_BMP1_Turret_INS_C::AT3_OnReloaded()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BMP1_Turret_INS_C", "AT3_OnReloaded");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_BMP1_Turret_INS_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BMP1_Turret_INS_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_BMP1_Turret_INS.BP_BMP1_Turret_INS_C.GetADSCameraLocationComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_BMP1_Turret_INS_C::GetADSCameraLocationComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_BMP1_Turret_INS_C", "GetADSCameraLocationComponent");

	Params::BP_BMP1_Turret_INS_C_GetADSCameraLocationComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

