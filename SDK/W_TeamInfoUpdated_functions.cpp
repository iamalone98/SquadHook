#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TeamInfoUpdated

#include "Basic.hpp"

#include "W_TeamInfoUpdated_classes.hpp"
#include "W_TeamInfoUpdated_parameters.hpp"


namespace SDK
{

// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.OnTeamChangePressed__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQTeamState*                     SelectedTeam                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::OnTeamChangePressed__DelegateSignature(class ASQTeamState* SelectedTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "OnTeamChangePressed__DelegateSignature");

	Params::W_TeamInfoUpdated_C_OnTeamChangePressed__DelegateSignature Parms{};

	Parms.SelectedTeam = SelectedTeam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.OnSizeValueChanged__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   NewParam                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::OnSizeValueChanged__DelegateSignature(float NewParam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "OnSizeValueChanged__DelegateSignature");

	Params::W_TeamInfoUpdated_C_OnSizeValueChanged__DelegateSignature Parms{};

	Parms.NewParam = NewParam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.TeamInfoSelected__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQFactionSetup*                  Param_FactionSetup                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   TeamId                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::TeamInfoSelected__DelegateSignature(class USQFactionSetup* Param_FactionSetup, int32 TeamId)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "TeamInfoSelected__DelegateSignature");

	Params::W_TeamInfoUpdated_C_TeamInfoSelected__DelegateSignature Parms{};

	Parms.Param_FactionSetup = Param_FactionSetup;
	Parms.TeamId = TeamId;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.ExecuteUbergraph_W_TeamInfoUpdated
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::ExecuteUbergraph_W_TeamInfoUpdated(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "ExecuteUbergraph_W_TeamInfoUpdated");

	Params::W_TeamInfoUpdated_C_ExecuteUbergraph_W_TeamInfoUpdated Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.BndEvt__W_TeamInfoUpdated_InfoButton_K2Node_ComponentBoundEvent_0_InfoClicked__DelegateSignature
// (BlueprintEvent)

void UW_TeamInfoUpdated_C::BndEvt__W_TeamInfoUpdated_InfoButton_K2Node_ComponentBoundEvent_0_InfoClicked__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "BndEvt__W_TeamInfoUpdated_InfoButton_K2Node_ComponentBoundEvent_0_InfoClicked__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_3_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UW_TeamInfoUpdated_C::BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_3_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_3_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_TeamInfoUpdated_C::BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_TeamInfoUpdated_C::BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "BndEvt__W_TeamInfoUpdated_Button_0_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Tick");

	Params::W_TeamInfoUpdated_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Refresh Live Info
// (BlueprintCallable, BlueprintEvent)

void UW_TeamInfoUpdated_C::Refresh_Live_Info()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Refresh Live Info");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Await Faction Setup
// (BlueprintCallable, BlueprintEvent)

void UW_TeamInfoUpdated_C::Await_Faction_Setup()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Await Faction Setup");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_TeamInfoUpdated_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Init Team
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBP_SQFactionSetup_C*             Faction                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::Init_Team(class UBP_SQFactionSetup_C* Faction)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Init Team");

	Params::W_TeamInfoUpdated_C_Init_Team Parms{};

	Parms.Faction = Faction;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Refresh
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_TeamInfoUpdated_C::Refresh()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Refresh");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.Get Team Image
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSQFactionEntry                  Faction_Entry                                          (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
// TSoftObjectPtr<class UTexture2D>        Team_Texture                                           (Parm, OutParm, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::Get_Team_Image(const struct FSQFactionEntry& Faction_Entry, TSoftObjectPtr<class UTexture2D>* Team_Texture)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "Get Team Image");

	Params::W_TeamInfoUpdated_C_Get_Team_Image Parms{};

	Parms.Faction_Entry = std::move(Faction_Entry);

	UObject::ProcessEvent(Func, &Parms);

	if (Team_Texture != nullptr)
		*Team_Texture = Parms.Team_Texture;
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.GetTeamState
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQTeamState*                     Output                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_TeamInfoUpdated_C::GetTeamState(class ASQTeamState** Output)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "GetTeamState");

	Params::W_TeamInfoUpdated_C_GetTeamState Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Output != nullptr)
		*Output = Parms.Output;
}


// Function W_TeamInfoUpdated.W_TeamInfoUpdated_C.OnRep_Is Selected
// (BlueprintCallable, BlueprintEvent)

void UW_TeamInfoUpdated_C::OnRep_Is_Selected()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_TeamInfoUpdated_C", "OnRep_Is Selected");

	UObject::ProcessEvent(Func, nullptr);
}

}
