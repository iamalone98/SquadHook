#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SmartDeployable

#include "Basic.hpp"

#include "BP_SmartDeployable_classes.hpp"
#include "BP_SmartDeployable_parameters.hpp"


namespace SDK
{

// Function BP_SmartDeployable.BP_SmartDeployable_C.ExecuteUbergraph_BP_SmartDeployable
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_SmartDeployable_C::ExecuteUbergraph_BP_SmartDeployable(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "ExecuteUbergraph_BP_SmartDeployable");

	Params::BP_SmartDeployable_C_ExecuteUbergraph_BP_SmartDeployable Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.BPStopUsed
// (Event, Public, BlueprintEvent)
// Parameters:
// class AController*                      User                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_SmartDeployable_C::BPStopUsed(class AController* User)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "BPStopUsed");

	Params::BP_SmartDeployable_C_BPStopUsed Parms{};

	Parms.User = User;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.CompletedConstruction
// (Event, Public, BlueprintEvent)

void ABP_SmartDeployable_C::CompletedConstruction()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "CompletedConstruction");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.SuccessfullyDeployed
// (BlueprintCallable, BlueprintEvent)

void ABP_SmartDeployable_C::SuccessfullyDeployed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "SuccessfullyDeployed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.BPOnUsed
// (Event, Public, BlueprintEvent)
// Parameters:
// class AController*                      User                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_SmartDeployable_C::BPOnUsed(class AController* User)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "BPOnUsed");

	Params::BP_SmartDeployable_C_BPOnUsed Parms{};

	Parms.User = User;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_SmartDeployable_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_SmartDeployable.BP_SmartDeployable_C.CreateRadialMenu
// (Protected, BlueprintCallable, BlueprintEvent)
// Parameters:
// class AController*                      Controller                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UObject*                          Context                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_SmartDeployable_C::CreateRadialMenu(class AController* Controller, class UObject* Context)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SmartDeployable_C", "CreateRadialMenu");

	Params::BP_SmartDeployable_C_CreateRadialMenu Parms{};

	Parms.Controller = Controller;
	Parms.Context = Context;

	UObject::ProcessEvent(Func, &Parms);
}

}
