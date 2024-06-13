#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MainMenu_Button

#include "Basic.hpp"

#include "MainMenu_Button_classes.hpp"
#include "MainMenu_Button_parameters.hpp"


namespace SDK
{

// Function MainMenu_Button.MainMenu_Button_C.OnClicked__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bSelected                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Param_Button                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UMainMenu_Button_C::OnClicked__DelegateSignature(bool Param_bSelected, class UMainMenu_Button_C* Param_Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "OnClicked__DelegateSignature");

	Params::MainMenu_Button_C_OnClicked__DelegateSignature Parms{};

	Parms.Param_bSelected = Param_bSelected;
	Parms.Param_Button = Param_Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.OnHover__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bHovered                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UMainMenu_Button_C::OnHover__DelegateSignature(bool Param_bHovered)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "OnHover__DelegateSignature");

	Params::MainMenu_Button_C_OnHover__DelegateSignature Parms{};

	Parms.Param_bHovered = Param_bHovered;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.OnDoubleClicked__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::OnDoubleClicked__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "OnDoubleClicked__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.ExecuteUbergraph_MainMenu_Button
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UMainMenu_Button_C::ExecuteUbergraph_MainMenu_Button(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "ExecuteUbergraph_MainMenu_Button");

	Params::MainMenu_Button_C_ExecuteUbergraph_MainMenu_Button Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UMainMenu_Button_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UMainMenu_Button_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "PreConstruct");

	Params::MainMenu_Button_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UMainMenu_Button_C::BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "BndEvt__Button_K2Node_ComponentBoundEvent_17_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UMainMenu_Button_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Tick");

	Params::MainMenu_Button_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.SetSelected
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bSelected                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UMainMenu_Button_C::SetSelected(bool Param_bSelected)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "SetSelected");

	Params::MainMenu_Button_C_SetSelected Parms{};

	Parms.Param_bSelected = Param_bSelected;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.UpdateColors
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::UpdateColors()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "UpdateColors");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.SetText
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (BlueprintVisible, BlueprintReadOnly, Parm)

void UMainMenu_Button_C::SetText(const class FText& Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "SetText");

	Params::MainMenu_Button_C_SetText Parms{};

	Parms.Text = std::move(Text);

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.Bind_LineColor
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FLinearColor                     ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

struct FLinearColor UMainMenu_Button_C::Bind_LineColor()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Bind_LineColor");

	Params::MainMenu_Button_C_Bind_LineColor Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function MainMenu_Button.MainMenu_Button_C.Bind_TextColor
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSlateColor                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateColor UMainMenu_Button_C::Bind_TextColor()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Bind_TextColor");

	Params::MainMenu_Button_C_Bind_TextColor Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function MainMenu_Button.MainMenu_Button_C.Update Button
// (Public, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::Update_Button()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Update Button");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.Setup Button
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::Setup_Button()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Setup Button");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.Refresh Line
// (Public, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::Refresh_Line()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "Refresh Line");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MainMenu_Button.MainMenu_Button_C.OnKeyDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FKeyEvent                        InKeyEvent                                             (BlueprintVisible, BlueprintReadOnly, Parm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UMainMenu_Button_C::OnKeyDown(const struct FGeometry& MyGeometry, const struct FKeyEvent& InKeyEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "OnKeyDown");

	Params::MainMenu_Button_C_OnKeyDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InKeyEvent = std::move(InKeyEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function MainMenu_Button.MainMenu_Button_C.UpdateNewContentDisplay
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bNewContent                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UMainMenu_Button_C::UpdateNewContentDisplay(bool Param_bNewContent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "UpdateNewContentDisplay");

	Params::MainMenu_Button_C_UpdateNewContentDisplay Parms{};

	Parms.Param_bNewContent = Param_bNewContent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MainMenu_Button.MainMenu_Button_C.UpdateIcon
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UMainMenu_Button_C::UpdateIcon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MainMenu_Button_C", "UpdateIcon");

	UObject::ProcessEvent(Func, nullptr);
}

}
