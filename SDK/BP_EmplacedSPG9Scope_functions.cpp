#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedSPG9Scope

#include "Basic.hpp"

#include "BP_EmplacedSPG9Scope_classes.hpp"
#include "BP_EmplacedSPG9Scope_parameters.hpp"


namespace SDK
{

// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.ExecuteUbergraph_BP_EmplacedSPG9Scope
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_EmplacedSPG9Scope_C::ExecuteUbergraph_BP_EmplacedSPG9Scope(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "ExecuteUbergraph_BP_EmplacedSPG9Scope");

	Params::BP_EmplacedSPG9Scope_C_ExecuteUbergraph_BP_EmplacedSPG9Scope Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.RemoveADS
// (BlueprintCallable, BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::RemoveADS()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "RemoveADS");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.CUnpossessed
// (BlueprintCallable, BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::CUnpossessed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "CUnpossessed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.CPossessed
// (BlueprintCallable, BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::CPossessed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "CPossessed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.BlueprintOnZoom
// (Event, Protected, BlueprintEvent)
// Parameters:
// bool                                    bNewZoom                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_EmplacedSPG9Scope_C::BlueprintOnZoom(bool bNewZoom)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "BlueprintOnZoom");

	Params::BP_EmplacedSPG9Scope_C_BlueprintOnZoom Parms{};

	Parms.bNewZoom = bNewZoom;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.Timeline_0__UpdateFunc
// (BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::Timeline_0__UpdateFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "Timeline_0__UpdateFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.Timeline_0__FinishedFunc
// (BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::Timeline_0__FinishedFunc()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "Timeline_0__FinishedFunc");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_EmplacedSPG9Scope.BP_EmplacedSPG9Scope_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_EmplacedSPG9Scope_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9Scope_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}

}

