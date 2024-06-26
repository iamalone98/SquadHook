#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericWorldIcon

#include "Basic.hpp"

#include "BP_GenericWorldIcon_classes.hpp"
#include "BP_GenericWorldIcon_parameters.hpp"


namespace SDK
{

// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.ExecuteUbergraph_BP_GenericWorldIcon
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericWorldIcon_C::ExecuteUbergraph_BP_GenericWorldIcon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "ExecuteUbergraph_BP_GenericWorldIcon");

	Params::BP_GenericWorldIcon_C_ExecuteUbergraph_BP_GenericWorldIcon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.OverrideDoFade
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Fade_In                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericWorldIcon_C::OverrideDoFade(bool Fade_In)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "OverrideDoFade");

	Params::BP_GenericWorldIcon_C_OverrideDoFade Parms{};

	Parms.Fade_In = Fade_In;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.OnDestroyed_Event_0
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class AActor*                           DestroyedActor                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericWorldIcon_C::OnDestroyed_Event_0(class AActor* DestroyedActor)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "OnDestroyed_Event_0");

	Params::BP_GenericWorldIcon_C_OnDestroyed_Event_0 Parms{};

	Parms.DestroyedActor = DestroyedActor;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.Check Distance
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericWorldIcon_C::Check_Distance()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "Check Distance");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_GenericWorldIcon_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_GenericWorldIcon_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.Should Be Visible
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool ABP_GenericWorldIcon_C::Should_Be_Visible()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "Should Be Visible");

	Params::BP_GenericWorldIcon_C_Should_Be_Visible Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_GenericWorldIcon.BP_GenericWorldIcon_C.Is Player Aiming Down Sights
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool ABP_GenericWorldIcon_C::Is_Player_Aiming_Down_Sights()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericWorldIcon_C", "Is Player Aiming Down Sights");

	Params::BP_GenericWorldIcon_C_Is_Player_Aiming_Down_Sights Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

