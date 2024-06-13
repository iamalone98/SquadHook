#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDeployableMortarVehicle

#include "Basic.hpp"

#include "BP_GenericDeployableMortarVehicle_classes.hpp"
#include "BP_GenericDeployableMortarVehicle_parameters.hpp"


namespace SDK
{

// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.ExecuteUbergraph_BP_GenericDeployableMortarVehicle
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::ExecuteUbergraph_BP_GenericDeployableMortarVehicle(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "ExecuteUbergraph_BP_GenericDeployableMortarVehicle");

	Params::BP_GenericDeployableMortarVehicle_C_ExecuteUbergraph_BP_GenericDeployableMortarVehicle Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.OnPlayerExited_Event
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQVehicle*                       Vehicle                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class APlayerController*                Player                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Seat                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::OnPlayerExited_Event(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "OnPlayerExited_Event");

	Params::BP_GenericDeployableMortarVehicle_C_OnPlayerExited_Event Parms{};

	Parms.Vehicle = Vehicle;
	Parms.Player = Player;
	Parms.Seat = Seat;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.OnPlayerEntered_Event
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQVehicle*                       Vehicle                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class APlayerController*                Player                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Seat                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::OnPlayerEntered_Event(class ASQVehicle* Vehicle, class APlayerController* Player, int32 Seat)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "OnPlayerEntered_Event");

	Params::BP_GenericDeployableMortarVehicle_C_OnPlayerEntered_Event Parms{};

	Parms.Vehicle = Vehicle;
	Parms.Player = Player;
	Parms.Seat = Seat;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.InpAxisEvt_LookUp_K2Node_InputAxisEvent_4
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::InpAxisEvt_LookUp_K2Node_InputAxisEvent_4(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "InpAxisEvt_LookUp_K2Node_InputAxisEvent_4");

	Params::BP_GenericDeployableMortarVehicle_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_4 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.InpAxisEvt_Turn_K2Node_InputAxisEvent_3
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::InpAxisEvt_Turn_K2Node_InputAxisEvent_3(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "InpAxisEvt_Turn_K2Node_InputAxisEvent_3");

	Params::BP_GenericDeployableMortarVehicle_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_3 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2");

	Params::BP_GenericDeployableMortarVehicle_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.ReceiveUnpossessed
// (Event, Public, BlueprintEvent)
// Parameters:
// class AController*                      OldController                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::ReceiveUnpossessed(class AController* OldController)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "ReceiveUnpossessed");

	Params::BP_GenericDeployableMortarVehicle_C_ReceiveUnpossessed Parms{};

	Parms.OldController = OldController;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0");

	Params::BP_GenericDeployableMortarVehicle_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0");

	Params::BP_GenericDeployableMortarVehicle_C_InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableMortarVehicle_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.LookUp
// (Event, Protected, BlueprintEvent)
// Parameters:
// float                                   Rate                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableMortarVehicle_C::LookUp(float Rate)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "LookUp");

	Params::BP_GenericDeployableMortarVehicle_C_LookUp Parms{};

	Parms.Rate = Rate;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableMortarVehicle_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableMortarVehicle.BP_GenericDeployableMortarVehicle_C.GetADSCameraLocationComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_GenericDeployableMortarVehicle_C::GetADSCameraLocationComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableMortarVehicle_C", "GetADSCameraLocationComponent");

	Params::BP_GenericDeployableMortarVehicle_C_GetADSCameraLocationComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

