#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_Slider_LR

#include "Basic.hpp"

#include "SettingsItem_Slider_LR_classes.hpp"
#include "SettingsItem_Slider_LR_parameters.hpp"


namespace SDK
{

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.OnValueChanged__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Param_Value                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::OnValueChanged__DelegateSignature(float Param_Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "OnValueChanged__DelegateSignature");

	Params::SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature Parms{};

	Parms.Param_Value = Param_Value;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.OnCaptureEnd__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Param_Value                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::OnCaptureEnd__DelegateSignature(float Param_Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "OnCaptureEnd__DelegateSignature");

	Params::SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature Parms{};

	Parms.Param_Value = Param_Value;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.ExecuteUbergraph_SettingsItem_Slider_LR
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::ExecuteUbergraph_SettingsItem_Slider_LR(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "ExecuteUbergraph_SettingsItem_Slider_LR");

	Params::SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__Slider_K2Node_ComponentBoundEvent_15_OnMouseCaptureEndEvent__DelegateSignature
// (BlueprintEvent)

void USettingsItem_Slider_LR_C::BndEvt__Slider_K2Node_ComponentBoundEvent_15_OnMouseCaptureEndEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "BndEvt__Slider_K2Node_ComponentBoundEvent_15_OnMouseCaptureEndEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USettingsItem_Slider_LR_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "PreConstruct");

	Params::SettingsItem_Slider_LR_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void USettingsItem_Slider_LR_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature
// (HasOutParams, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// ETextCommit                             CommitMethod                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature(const class FText& Text, ETextCommit CommitMethod)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature");

	Params::SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature Parms{};

	Parms.Text = std::move(Text);
	Parms.CommitMethod = CommitMethod;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature
// (HasOutParams, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)

void USettingsItem_Slider_LR_C::BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature(const class FText& Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature");

	Params::SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature Parms{};

	Parms.Text = std::move(Text);

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature
// (BlueprintEvent)
// Parameters:
// float                                   Param_Value                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature(float Param_Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature");

	Params::SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature Parms{};

	Parms.Param_Value = Param_Value;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.SetValue
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Param_Value                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USettingsItem_Slider_LR_C::SetValue(float Param_Value)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "SetValue");

	Params::SettingsItem_Slider_LR_C_SetValue Parms{};

	Parms.Param_Value = Param_Value;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.UpdateSliderTextValue
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void USettingsItem_Slider_LR_C::UpdateSliderTextValue()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "UpdateSliderTextValue");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.UpdateSliderValue
// (Public, BlueprintCallable, BlueprintEvent)

void USettingsItem_Slider_LR_C::UpdateSliderValue()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "UpdateSliderValue");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.Get_SpacerImg_Brush_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FSlateBrush                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateBrush USettingsItem_Slider_LR_C::Get_SpacerImg_Brush_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "Get_SpacerImg_Brush_0");

	Params::SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.RemovePercentage
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class FText                             InText                                                 (BlueprintVisible, BlueprintReadOnly, Parm)
// class FText                             OutText                                                (Parm, OutParm)

void USettingsItem_Slider_LR_C::RemovePercentage(const class FText& InText, class FText* OutText) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SettingsItem_Slider_LR_C", "RemovePercentage");

	Params::SettingsItem_Slider_LR_C_RemovePercentage Parms{};

	Parms.InText = std::move(InText);

	UObject::ProcessEvent(Func, &Parms);

	if (OutText != nullptr)
		*OutText = std::move(Parms.OutText);
}

}
