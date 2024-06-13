#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CamControlButton

#include "Basic.hpp"

#include "W_CamControlButton_classes.hpp"
#include "W_CamControlButton_parameters.hpp"


namespace SDK
{

// Function W_CamControlButton.W_CamControlButton_C.Cam State Changed__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Active                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class ABP_ControlledCamera_C*           Cam                                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CamControlButton_C::Cam_State_Changed__DelegateSignature(bool Active, class ABP_ControlledCamera_C* Cam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Cam State Changed__DelegateSignature");

	Params::W_CamControlButton_C_Cam_State_Changed__DelegateSignature Parms{};

	Parms.Active = Active;
	Parms.Cam = Cam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CamControlButton.W_CamControlButton_C.ExecuteUbergraph_W_CamControlButton
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CamControlButton_C::ExecuteUbergraph_W_CamControlButton(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "ExecuteUbergraph_W_CamControlButton");

	Params::W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CamControlButton.W_CamControlButton_C.Fail Message
// (BlueprintCallable, BlueprintEvent)

void UW_CamControlButton_C::Fail_Message()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Fail Message");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CamControlButton.W_CamControlButton_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_CamControlButton_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "PreConstruct");

	Params::W_CamControlButton_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CamControlButton.W_CamControlButton_C.Remove Camera Button
// (BlueprintCallable, BlueprintEvent)

void UW_CamControlButton_C::Remove_Camera_Button()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Remove Camera Button");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CamControlButton.W_CamControlButton_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_CamControlButton_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CamControlButton.W_CamControlButton_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CamControlButton_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Tick");

	Params::W_CamControlButton_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CamControlButton.W_CamControlButton_C.BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UW_CamControlButton_C::BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CamControlButton.W_CamControlButton_C.Update Remote Camera Button
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_CamControlButton_C::Update_Remote_Camera_Button()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Update Remote Camera Button");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CamControlButton.W_CamControlButton_C.Can Use Button
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Valid                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_CamControlButton_C::Can_Use_Button(bool* Valid)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Can Use Button");

	Params::W_CamControlButton_C_Can_Use_Button Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Valid != nullptr)
		*Valid = Parms.Valid;
}


// Function W_CamControlButton.W_CamControlButton_C.Get Tooltip
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidget*                          ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UWidget* UW_CamControlButton_C::Get_Tooltip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Get Tooltip");

	Params::W_CamControlButton_C_Get_Tooltip Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_CamControlButton.W_CamControlButton_C.Validate Vehicle Action
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Allowed                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_CamControlButton_C::Validate_Vehicle_Action(bool* Allowed)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CamControlButton_C", "Validate Vehicle Action");

	Params::W_CamControlButton_C_Validate_Vehicle_Action Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Allowed != nullptr)
		*Allowed = Parms.Allowed;
}

}

