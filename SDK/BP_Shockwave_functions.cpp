#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Shockwave

#include "Basic.hpp"

#include "BP_Shockwave_classes.hpp"
#include "BP_Shockwave_parameters.hpp"


namespace SDK
{

// Function BP_Shockwave.BP_Shockwave_C.ExecuteUbergraph_BP_Shockwave
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Shockwave_C::ExecuteUbergraph_BP_Shockwave(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Shockwave_C", "ExecuteUbergraph_BP_Shockwave");

	Params::BP_Shockwave_C_ExecuteUbergraph_BP_Shockwave Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Shockwave.BP_Shockwave_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_Shockwave_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Shockwave_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Shockwave.BP_Shockwave_C.Explode
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class AActor*                           Param_Instigator                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Shockwave_C::Explode(class AActor* Param_Instigator)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Shockwave_C", "Explode");

	Params::BP_Shockwave_C_Explode Parms{};

	Parms.Param_Instigator = Param_Instigator;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Shockwave.BP_Shockwave_C.ConvertStepsToLoops
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   Steps                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   PositiveInt                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   NegativeInt                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Shockwave_C::ConvertStepsToLoops(int32 Steps, int32* PositiveInt, int32* NegativeInt)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Shockwave_C", "ConvertStepsToLoops");

	Params::BP_Shockwave_C_ConvertStepsToLoops Parms{};

	Parms.Steps = Steps;

	UObject::ProcessEvent(Func, &Parms);

	if (PositiveInt != nullptr)
		*PositiveInt = Parms.PositiveInt;

	if (NegativeInt != nullptr)
		*NegativeInt = Parms.NegativeInt;
}


// Function BP_Shockwave.BP_Shockwave_C.SpawnEmitterAtTraceIntersect
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          StartTrace                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FVector                          EndTrace                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class AActor*                           Param_Instigator                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Shockwave_C::SpawnEmitterAtTraceIntersect(const struct FVector& StartTrace, const struct FVector& EndTrace, class AActor* Param_Instigator)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Shockwave_C", "SpawnEmitterAtTraceIntersect");

	Params::BP_Shockwave_C_SpawnEmitterAtTraceIntersect Parms{};

	Parms.StartTrace = std::move(StartTrace);
	Parms.EndTrace = std::move(EndTrace);
	Parms.Param_Instigator = Param_Instigator;

	UObject::ProcessEvent(Func, &Parms);
}

}
