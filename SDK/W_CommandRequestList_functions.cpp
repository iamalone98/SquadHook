#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandRequestList

#include "Basic.hpp"

#include "W_CommandRequestList_classes.hpp"
#include "W_CommandRequestList_parameters.hpp"


namespace SDK
{

// Function W_CommandRequestList.W_CommandRequestList_C.ExecuteUbergraph_W_CommandRequestList
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandRequestList_C::ExecuteUbergraph_W_CommandRequestList(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "ExecuteUbergraph_W_CommandRequestList");

	Params::W_CommandRequestList_C_ExecuteUbergraph_W_CommandRequestList Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Placement Complete
// (BlueprintCallable, BlueprintEvent)

void UW_CommandRequestList_C::Placement_Complete()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Placement Complete");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Control Widget Created
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UW_Command_ActionControl_C*       Widget                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandRequestList_C::Control_Widget_Created(class UW_Command_ActionControl_C* Widget)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Control Widget Created");

	Params::W_CommandRequestList_C_Control_Widget_Created Parms{};

	Parms.Widget = Widget;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Remove list
// (BlueprintCallable, BlueprintEvent)

void UW_CommandRequestList_C::Remove_list()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Remove list");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_CommandRequestList_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandRequestList.W_CommandRequestList_C.BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandRequestList_C::BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");

	Params::W_CommandRequestList_C_BndEvt__Button_Deny_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandRequestList.W_CommandRequestList_C.BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandRequestList_C::BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature");

	Params::W_CommandRequestList_C_BndEvt__Button_Accept_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Remove Other Request Lists
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_CommandRequestList_C::Remove_Other_Request_Lists()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Remove Other Request Lists");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandRequestList.W_CommandRequestList_C.Init Action List
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_CommandRequestList_C::Init_Action_List()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandRequestList_C", "Init Action List");

	UObject::ProcessEvent(Func, nullptr);
}

}
