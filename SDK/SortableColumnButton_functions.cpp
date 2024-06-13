#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SortableColumnButton

#include "Basic.hpp"

#include "SortableColumnButton_classes.hpp"
#include "SortableColumnButton_parameters.hpp"


namespace SDK
{

// Function SortableColumnButton.SortableColumnButton_C.OnClicked__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    bIsAscending                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// E_SortType                              Param_Sort_Type                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USortableColumnButton_C::OnClicked__DelegateSignature(bool bIsAscending, E_SortType Param_Sort_Type)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "OnClicked__DelegateSignature");

	Params::SortableColumnButton_C_OnClicked__DelegateSignature Parms{};

	Parms.bIsAscending = bIsAscending;
	Parms.Param_Sort_Type = Param_Sort_Type;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.OnHover__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bHovered                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USortableColumnButton_C::OnHover__DelegateSignature(bool Param_bHovered)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "OnHover__DelegateSignature");

	Params::SortableColumnButton_C_OnHover__DelegateSignature Parms{};

	Parms.Param_bHovered = Param_bHovered;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.ExecuteUbergraph_SortableColumnButton
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USortableColumnButton_C::ExecuteUbergraph_SortableColumnButton(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "ExecuteUbergraph_SortableColumnButton");

	Params::SortableColumnButton_C_ExecuteUbergraph_SortableColumnButton Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USortableColumnButton_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "PreConstruct");

	Params::SortableColumnButton_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void USortableColumnButton_C::BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SortableColumnButton.SortableColumnButton_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USortableColumnButton_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Tick");

	Params::SortableColumnButton_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void USortableColumnButton_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SortableColumnButton.SortableColumnButton_C.Set Selected
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bSelected                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USortableColumnButton_C::Set_Selected(bool Param_bSelected)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Set Selected");

	Params::SortableColumnButton_C_Set_Selected Parms{};

	Parms.Param_bSelected = Param_bSelected;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.Update Widget
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void USortableColumnButton_C::Update_Widget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Update Widget");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SortableColumnButton.SortableColumnButton_C.Set Text
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (BlueprintVisible, BlueprintReadOnly, Parm)

void USortableColumnButton_C::Set_Text(const class FText& Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Set Text");

	Params::SortableColumnButton_C_Set_Text Parms{};

	Parms.Text = std::move(Text);

	UObject::ProcessEvent(Func, &Parms);
}


// Function SortableColumnButton.SortableColumnButton_C.Set Arrow
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// ESlateVisibility                        ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

ESlateVisibility USortableColumnButton_C::Set_Arrow()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Set Arrow");

	Params::SortableColumnButton_C_Set_Arrow Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function SortableColumnButton.SortableColumnButton_C.Set Sort State
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// ESQSortStates                           Param_SortState                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Param_bSelected                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USortableColumnButton_C::Set_Sort_State(ESQSortStates Param_SortState, bool Param_bSelected)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SortableColumnButton_C", "Set Sort State");

	Params::SortableColumnButton_C_Set_Sort_State Parms{};

	Parms.Param_SortState = Param_SortState;
	Parms.Param_bSelected = Param_bSelected;

	UObject::ProcessEvent(Func, &Parms);
}

}

