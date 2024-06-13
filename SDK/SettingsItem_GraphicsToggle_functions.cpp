#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_GraphicsToggle

#include "Basic.hpp"

#include "SettingsItem_GraphicsToggle_classes.hpp"
#include "SettingsItem_GraphicsToggle_parameters.hpp"


namespace SDK
{

// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.OnButtonClick__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   ButtonNumber                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USettingsItem_GraphicsToggle_C*   ToggleItem                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_GraphicsToggle_C::OnButtonClick__DelegateSignature(int32 ButtonNumber, class USettingsItem_GraphicsToggle_C* ToggleItem)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "OnButtonClick__DelegateSignature");

	Params::SettingsItem_GraphicsToggle_C_OnButtonClick__DelegateSignature Parms{};

	Parms.ButtonNumber = ButtonNumber;
	Parms.ToggleItem = ToggleItem;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.ExecuteUbergraph_SettingsItem_GraphicsToggle
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_GraphicsToggle_C::ExecuteUbergraph_SettingsItem_GraphicsToggle(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "ExecuteUbergraph_SettingsItem_GraphicsToggle");

	Params::SettingsItem_GraphicsToggle_C_ExecuteUbergraph_SettingsItem_GraphicsToggle Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.On Button Clicked
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class USetting_Button_C*                Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_GraphicsToggle_C::On_Button_Clicked(bool bSelected, class USetting_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "On Button Clicked");

	Params::SettingsItem_GraphicsToggle_C_On_Button_Clicked Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.Create Buttons
// (BlueprintCallable, BlueprintEvent)

void USettingsItem_GraphicsToggle_C::Create_Buttons()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "Create Buttons");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USettingsItem_GraphicsToggle_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "PreConstruct");

	Params::SettingsItem_GraphicsToggle_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void USettingsItem_GraphicsToggle_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.SetSelected
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   Param_Index                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_GraphicsToggle_C::SetSelected(int32 Param_Index)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "SetSelected");

	Params::SettingsItem_GraphicsToggle_C_SetSelected Parms{};

	Parms.Param_Index = Param_Index;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.GetBrush
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSlateBrush                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateBrush USettingsItem_GraphicsToggle_C::GetBrush()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "GetBrush");

	Params::SettingsItem_GraphicsToggle_C_GetBrush Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C.Setup Button
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             ButtonText                                             (BlueprintVisible, BlueprintReadOnly, Parm)
// struct FColoredTextStruct               Inherit_Text                                           (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
// class USetting_Button_C*                ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USetting_Button_C* USettingsItem_GraphicsToggle_C::Setup_Button(const class FText& ButtonText, const struct FColoredTextStruct& Inherit_Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_GraphicsToggle_C", "Setup Button");

	Params::SettingsItem_GraphicsToggle_C_Setup_Button Parms{};

	Parms.ButtonText = std::move(ButtonText);
	Parms.Inherit_Text = std::move(Inherit_Text);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

