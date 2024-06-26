#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_BaseSettingOption

#include "Basic.hpp"

#include "W_BaseSettingOption_classes.hpp"
#include "W_BaseSettingOption_parameters.hpp"


namespace SDK
{

// Function W_BaseSettingOption.W_BaseSettingOption_C.OnRefresh__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             SettingName                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FString                           Value                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)

void UW_BaseSettingOption_C::OnRefresh__DelegateSignature(class FName SettingName, const class FString& Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "OnRefresh__DelegateSignature");

	Params::W_BaseSettingOption_C_OnRefresh__DelegateSignature Parms{};

	Parms.SettingName = SettingName;
	Parms.Value = std::move(Value);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.OnSet__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             Setting_Name                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FString                           Value                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)

void UW_BaseSettingOption_C::OnSet__DelegateSignature(class FName Setting_Name, const class FString& Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "OnSet__DelegateSignature");

	Params::W_BaseSettingOption_C_OnSet__DelegateSignature Parms{};

	Parms.Setting_Name = Setting_Name;
	Parms.Value = std::move(Value);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.ExecuteUbergraph_W_BaseSettingOption
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_BaseSettingOption_C::ExecuteUbergraph_W_BaseSettingOption(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "ExecuteUbergraph_W_BaseSettingOption");

	Params::W_BaseSettingOption_C_ExecuteUbergraph_W_BaseSettingOption Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.OnInitialized
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_BaseSettingOption_C::OnInitialized()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "OnInitialized");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.GetToolTipWidget
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidget*                          ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UWidget* UW_BaseSettingOption_C::GetToolTipWidget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "GetToolTipWidget");

	Params::W_BaseSettingOption_C_GetToolTipWidget Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.RefreshSettings
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             SettingName                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FString                           Value                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)

void UW_BaseSettingOption_C::RefreshSettings(class FName SettingName, const class FString& Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "RefreshSettings");

	Params::W_BaseSettingOption_C_RefreshSettings Parms{};

	Parms.SettingName = SettingName;
	Parms.Value = std::move(Value);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.SetSettingValue
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FName                             Setting_Name                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FString                           Value                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)

void UW_BaseSettingOption_C::SetSettingValue(class FName Setting_Name, const class FString& Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "SetSettingValue");

	Params::W_BaseSettingOption_C_SetSettingValue Parms{};

	Parms.Setting_Name = Setting_Name;
	Parms.Value = std::move(Value);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BaseSettingOption.W_BaseSettingOption_C.CreateWidget
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UWidget*                          WidgetIn                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FLinearColor                     Color                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UUMG_Tooltip_C*                   ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UUMG_Tooltip_C* UW_BaseSettingOption_C::CreateWidget(class UWidget* WidgetIn, const struct FLinearColor& Color)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BaseSettingOption_C", "CreateWidget");

	Params::W_BaseSettingOption_C_CreateWidget Parms{};

	Parms.WidgetIn = WidgetIn;
	Parms.Color = std::move(Color);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

