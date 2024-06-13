#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GameMode

#include "Basic.hpp"

#include "BP_GameMode_classes.hpp"
#include "BP_GameMode_parameters.hpp"


namespace SDK
{

// Function BP_GameMode.BP_GameMode_C.ExecuteUbergraph_BP_GameMode
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GameMode_C::ExecuteUbergraph_BP_GameMode(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GameMode_C", "ExecuteUbergraph_BP_GameMode");

	Params::BP_GameMode_C_ExecuteUbergraph_BP_GameMode Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GameMode.BP_GameMode_C.ReceiveEndPlay
// (Event, Protected, BlueprintEvent)
// Parameters:
// EEndPlayReason                          EndPlayReason                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GameMode_C::ReceiveEndPlay(EEndPlayReason EndPlayReason)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GameMode_C", "ReceiveEndPlay");

	Params::BP_GameMode_C_ReceiveEndPlay Parms{};

	Parms.EndPlayReason = EndPlayReason;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GameMode.BP_GameMode_C.GetConcretePawnClassForController
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class AController*                      InController                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// TSubclassOf<class ASQSoldier>           ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash)

TSubclassOf<class ASQSoldier> ABP_GameMode_C::GetConcretePawnClassForController(class AController* InController)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GameMode_C", "GetConcretePawnClassForController");

	Params::BP_GameMode_C_GetConcretePawnClassForController Parms{};

	Parms.InController = InController;

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

