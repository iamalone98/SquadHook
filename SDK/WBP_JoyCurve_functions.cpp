#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: WBP_JoyCurve

#include "Basic.hpp"

#include "WBP_JoyCurve_classes.hpp"
#include "WBP_JoyCurve_parameters.hpp"


namespace SDK
{

// Function WBP_JoyCurve.WBP_JoyCurve_C.ExecuteUbergraph_WBP_JoyCurve
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::ExecuteUbergraph_WBP_JoyCurve(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "ExecuteUbergraph_WBP_JoyCurve");

	Params::WBP_JoyCurve_C_ExecuteUbergraph_WBP_JoyCurve Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UWBP_JoyCurve_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "PreConstruct");

	Params::WBP_JoyCurve_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.ForceUpdate
// (BlueprintCallable, BlueprintEvent)

void UWBP_JoyCurve_C::ForceUpdate()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "ForceUpdate");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.BndEvt__DeadzoneControl_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature
// (BlueprintEvent)
// Parameters:
// float                                   NewParam                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::BndEvt__DeadzoneControl_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature(float NewParam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "BndEvt__DeadzoneControl_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature");

	Params::WBP_JoyCurve_C_BndEvt__DeadzoneControl_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature Parms{};

	Parms.NewParam = NewParam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.BndEvt__W_Slider_K2Node_ComponentBoundEvent_1_OnValueChanged__DelegateSignature
// (BlueprintEvent)
// Parameters:
// float                                   NewParam                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::BndEvt__W_Slider_K2Node_ComponentBoundEvent_1_OnValueChanged__DelegateSignature(float NewParam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "BndEvt__W_Slider_K2Node_ComponentBoundEvent_1_OnValueChanged__DelegateSignature");

	Params::WBP_JoyCurve_C_BndEvt__W_Slider_K2Node_ComponentBoundEvent_1_OnValueChanged__DelegateSignature Parms{};

	Parms.NewParam = NewParam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UWBP_JoyCurve_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.BndEvt__ComboBoxString_1105_K2Node_ComponentBoundEvent_3_OnSelectionChangedEvent__DelegateSignature
// (BlueprintEvent)
// Parameters:
// class FString                           SelectedItem                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
// ESelectInfo                             SelectionType                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::BndEvt__ComboBoxString_1105_K2Node_ComponentBoundEvent_3_OnSelectionChangedEvent__DelegateSignature(const class FString& SelectedItem, ESelectInfo SelectionType)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "BndEvt__ComboBoxString_1105_K2Node_ComponentBoundEvent_3_OnSelectionChangedEvent__DelegateSignature");

	Params::WBP_JoyCurve_C_BndEvt__ComboBoxString_1105_K2Node_ComponentBoundEvent_3_OnSelectionChangedEvent__DelegateSignature Parms{};

	Parms.SelectedItem = std::move(SelectedItem);
	Parms.SelectionType = SelectionType;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.BndEvt__CheckBox_356_K2Node_ComponentBoundEvent_4_OnCheckBoxComponentStateChanged__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bIsChecked                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UWBP_JoyCurve_C::BndEvt__CheckBox_356_K2Node_ComponentBoundEvent_4_OnCheckBoxComponentStateChanged__DelegateSignature(bool bIsChecked)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "BndEvt__CheckBox_356_K2Node_ComponentBoundEvent_4_OnCheckBoxComponentStateChanged__DelegateSignature");

	Params::WBP_JoyCurve_C_BndEvt__CheckBox_356_K2Node_ComponentBoundEvent_4_OnCheckBoxComponentStateChanged__DelegateSignature Parms{};

	Parms.bIsChecked = bIsChecked;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.RefreshMat
// (BlueprintCallable, BlueprintEvent)

void UWBP_JoyCurve_C::RefreshMat()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "RefreshMat");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Tick");

	Params::WBP_JoyCurve_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Create_MID
// (Public, BlueprintCallable, BlueprintEvent)

void UWBP_JoyCurve_C::Create_MID()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Create_MID");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Update_MID
// (Public, BlueprintCallable, BlueprintEvent)

void UWBP_JoyCurve_C::Update_MID()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Update_MID");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.GetCurveText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UWBP_JoyCurve_C::GetCurveText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "GetCurveText");

	Params::WBP_JoyCurve_C_GetCurveText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.GetDeadZoneValText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UWBP_JoyCurve_C::GetDeadZoneValText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "GetDeadZoneValText");

	Params::WBP_JoyCurve_C_GetDeadZoneValText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.GetSensitivityText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UWBP_JoyCurve_C::GetSensitivityText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "GetSensitivityText");

	Params::WBP_JoyCurve_C_GetSensitivityText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.SensitivityPreview
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Out                                                    (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UWBP_JoyCurve_C::SensitivityPreview(float* Out)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "SensitivityPreview");

	Params::WBP_JoyCurve_C_SensitivityPreview Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Out != nullptr)
		*Out = Parms.Out;
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.PopulateDefaults
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FSQJoyStickConfig                SQJoyStickConfig                                       (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)

void UWBP_JoyCurve_C::PopulateDefaults(const struct FSQJoyStickConfig& SQJoyStickConfig)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "PopulateDefaults");

	Params::WBP_JoyCurve_C_PopulateDefaults Parms{};

	Parms.SQJoyStickConfig = std::move(SQJoyStickConfig);

	UObject::ProcessEvent(Func, &Parms);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.SaveSettings
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UWBP_JoyCurve_C::SaveSettings()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "SaveSettings");

	UObject::ProcessEvent(Func, nullptr);
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Get_AxisText_Text_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UWBP_JoyCurve_C::Get_AxisText_Text_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Get_AxisText_Text_0");

	Params::WBP_JoyCurve_C_Get_AxisText_Text_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function WBP_JoyCurve.WBP_JoyCurve_C.Get Axis Deadzone
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// float                                   ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

float UWBP_JoyCurve_C::Get_Axis_Deadzone()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("WBP_JoyCurve_C", "Get Axis Deadzone");

	Params::WBP_JoyCurve_C_Get_Axis_Deadzone Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
