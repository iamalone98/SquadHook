#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: AnimBP_UH60

#include "Basic.hpp"

#include "AnimBP_UH60_classes.hpp"
#include "AnimBP_UH60_parameters.hpp"


namespace SDK
{

// Function AnimBP_UH60.AnimBP_UH60_C.ExecuteUbergraph_AnimBP_UH60
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UAnimBP_UH60_C::ExecuteUbergraph_AnimBP_UH60(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "ExecuteUbergraph_AnimBP_UH60");

	Params::AnimBP_UH60_C_ExecuteUbergraph_AnimBP_UH60 Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function AnimBP_UH60.AnimBP_UH60_C.BlueprintUpdateAnimation
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   DeltaTimeX                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UAnimBP_UH60_C::BlueprintUpdateAnimation(float DeltaTimeX)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "BlueprintUpdateAnimation");

	Params::AnimBP_UH60_C_BlueprintUpdateAnimation Parms{};

	Parms.DeltaTimeX = DeltaTimeX;

	UObject::ProcessEvent(Func, &Parms);
}


// Function AnimBP_UH60.AnimBP_UH60_C.GetCurrentRotorRPM
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class ABP_Generic_Helicopter_C*         Helicopter                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Main                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// float                                   RPM                                                    (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UAnimBP_UH60_C::GetCurrentRotorRPM(class ABP_Generic_Helicopter_C* Helicopter, bool Main, float* RPM)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "GetCurrentRotorRPM");

	Params::AnimBP_UH60_C_GetCurrentRotorRPM Parms{};

	Parms.Helicopter = Helicopter;
	Parms.Main = Main;

	UObject::ProcessEvent(Func, &Parms);

	if (RPM != nullptr)
		*RPM = Parms.RPM;
}


// Function AnimBP_UH60.AnimBP_UH60_C.RPMtoDegPerSec
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// float                                   RPM                                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    MainRotor                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class ABP_UH60_C*                       Helicopter                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   DegPerSec                                              (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UAnimBP_UH60_C::RPMtoDegPerSec(float RPM, bool MainRotor, class ABP_UH60_C* Helicopter, float* DegPerSec)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "RPMtoDegPerSec");

	Params::AnimBP_UH60_C_RPMtoDegPerSec Parms{};

	Parms.RPM = RPM;
	Parms.MainRotor = MainRotor;
	Parms.Helicopter = Helicopter;

	UObject::ProcessEvent(Func, &Parms);

	if (DegPerSec != nullptr)
		*DegPerSec = Parms.DegPerSec;
}


// Function AnimBP_UH60.AnimBP_UH60_C.GetBladesScale
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ABP_Generic_Helicopter_C*         Helicopter                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Main                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// struct FVector                          Blades                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FVector                          BlurBlades                                             (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UAnimBP_UH60_C::GetBladesScale(class ABP_Generic_Helicopter_C* Helicopter, bool Main, struct FVector* Blades, struct FVector* BlurBlades)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "GetBladesScale");

	Params::AnimBP_UH60_C_GetBladesScale Parms{};

	Parms.Helicopter = Helicopter;
	Parms.Main = Main;

	UObject::ProcessEvent(Func, &Parms);

	if (Blades != nullptr)
		*Blades = std::move(Parms.Blades);

	if (BlurBlades != nullptr)
		*BlurBlades = std::move(Parms.BlurBlades);
}


// Function AnimBP_UH60.AnimBP_UH60_C.AnimGraph
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPoseLink                        Param_AnimGraph                                        (Parm, OutParm, NoDestructor)

void UAnimBP_UH60_C::AnimGraph(struct FPoseLink* Param_AnimGraph)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("AnimBP_UH60_C", "AnimGraph");

	Params::AnimBP_UH60_C_AnimGraph Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_AnimGraph != nullptr)
		*Param_AnimGraph = std::move(Parms.Param_AnimGraph);
}

}

