#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: VoiceAction_Component

#include "Basic.hpp"

#include "VoiceAction_Component_classes.hpp"
#include "VoiceAction_Component_parameters.hpp"


namespace SDK
{

// Function VoiceAction_Component.VoiceAction_Component_C.ExecuteUbergraph_VoiceAction_Component
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoiceAction_Component_C::ExecuteUbergraph_VoiceAction_Component(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoiceAction_Component_C", "ExecuteUbergraph_VoiceAction_Component");

	Params::VoiceAction_Component_C_ExecuteUbergraph_VoiceAction_Component Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoiceAction_Component.VoiceAction_Component_C.Server Play Voice
// (Net, NetServer, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USoundBase*                       Sound                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoiceAction_Component_C::Server_Play_Voice(class USoundBase* Sound)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoiceAction_Component_C", "Server Play Voice");

	Params::VoiceAction_Component_C_Server_Play_Voice Parms{};

	Parms.Sound = Sound;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoiceAction_Component.VoiceAction_Component_C.Multicast Voice
// (Net, NetReliable, NetMulticast, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USoundBase*                       Sound                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UVoiceAction_Component_C::Multicast_Voice(class USoundBase* Sound)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoiceAction_Component_C", "Multicast Voice");

	Params::VoiceAction_Component_C_Multicast_Voice Parms{};

	Parms.Sound = Sound;

	UObject::ProcessEvent(Func, &Parms);
}


// Function VoiceAction_Component.VoiceAction_Component_C.Try to Play Voice
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USoundBase*                       Voice                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Played                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UVoiceAction_Component_C::Try_to_Play_Voice(class USoundBase* Voice, bool* Played)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("VoiceAction_Component_C", "Try to Play Voice");

	Params::VoiceAction_Component_C_Try_to_Play_Voice Parms{};

	Parms.Voice = Voice;

	UObject::ProcessEvent(Func, &Parms);

	if (Played != nullptr)
		*Played = Parms.Played;
}

}

