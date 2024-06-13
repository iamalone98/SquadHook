#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_DeploymentTutorial

#include "Basic.hpp"

#include "W_DeploymentTutorial_classes.hpp"
#include "W_DeploymentTutorial_parameters.hpp"


namespace SDK
{

// Function W_DeploymentTutorial.W_DeploymentTutorial_C.ExecuteUbergraph_W_DeploymentTutorial
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::ExecuteUbergraph_W_DeploymentTutorial(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "ExecuteUbergraph_W_DeploymentTutorial");

	Params::W_DeploymentTutorial_C_ExecuteUbergraph_W_DeploymentTutorial Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.OnModeIntroDisplayed
// (BlueprintCallable, BlueprintEvent)

void UW_DeploymentTutorial_C::OnModeIntroDisplayed()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "OnModeIntroDisplayed");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.End Tutorial
// (BlueprintCallable, BlueprintEvent)

void UW_DeploymentTutorial_C::End_Tutorial()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "End Tutorial");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.End of Tutorial 1
// (BlueprintCallable, BlueprintEvent)

void UW_DeploymentTutorial_C::End_of_Tutorial_1()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "End of Tutorial 1");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.BndEvt__ButtonRoleNext_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::BndEvt__ButtonRoleNext_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "BndEvt__ButtonRoleNext_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature");

	Params::W_DeploymentTutorial_C_BndEvt__ButtonRoleNext_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.Squad Select 2
// (BlueprintCallable, BlueprintEvent)

void UW_DeploymentTutorial_C::Squad_Select_2()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "Squad Select 2");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "Tick");

	Params::W_DeploymentTutorial_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.Squad Select 1
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQTeamState*                     Team                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::Squad_Select_1(class ASQTeamState* Team)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "Squad Select 1");

	Params::W_DeploymentTutorial_C_Squad_Select_1 Parms{};

	Parms.Team = Team;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.BndEvt__Button_TeamSelect1_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::BndEvt__Button_TeamSelect1_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "BndEvt__Button_TeamSelect1_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature");

	Params::W_DeploymentTutorial_C_BndEvt__Button_TeamSelect1_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.BndEvt__Skip_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::BndEvt__Skip_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "BndEvt__Skip_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");

	Params::W_DeploymentTutorial_C_BndEvt__Skip_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.BndEvt__Show_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_DeploymentTutorial_C::BndEvt__Show_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "BndEvt__Show_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature");

	Params::W_DeploymentTutorial_C_BndEvt__Show_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_DeploymentTutorial.W_DeploymentTutorial_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_DeploymentTutorial_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_DeploymentTutorial_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}

