#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RHIB_Transport

#include "Basic.hpp"

#include "BP_RHIB_Transport_classes.hpp"
#include "BP_RHIB_Transport_parameters.hpp"


namespace SDK
{

// Function BP_RHIB_Transport.BP_RHIB_Transport_C.ExecuteUbergraph_BP_RHIB_Transport
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_RHIB_Transport_C::ExecuteUbergraph_BP_RHIB_Transport(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RHIB_Transport_C", "ExecuteUbergraph_BP_RHIB_Transport");

	Params::BP_RHIB_Transport_C_ExecuteUbergraph_BP_RHIB_Transport Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RHIB_Transport.BP_RHIB_Transport_C.AttemptFindFlagTexture
// (BlueprintCallable, BlueprintEvent)

void ABP_RHIB_Transport_C::AttemptFindFlagTexture()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RHIB_Transport_C", "AttemptFindFlagTexture");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_RHIB_Transport.BP_RHIB_Transport_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_RHIB_Transport_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RHIB_Transport_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_RHIB_Transport.BP_RHIB_Transport_C.OnLoaded_53BB6EC540A8B1C8E9FF71B327568EB8
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UObject*                          Loaded                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_RHIB_Transport_C::OnLoaded_53BB6EC540A8B1C8E9FF71B327568EB8(class UObject* Loaded)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RHIB_Transport_C", "OnLoaded_53BB6EC540A8B1C8E9FF71B327568EB8");

	Params::BP_RHIB_Transport_C_OnLoaded_53BB6EC540A8B1C8E9FF71B327568EB8 Parms{};

	Parms.Loaded = Loaded;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_RHIB_Transport.BP_RHIB_Transport_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_RHIB_Transport_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_RHIB_Transport_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}

}
