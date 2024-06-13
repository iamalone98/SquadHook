#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ControlledCamera

#include "Basic.hpp"

#include "BP_ControlledCamera_classes.hpp"
#include "BP_ControlledCamera_parameters.hpp"


namespace SDK
{

// Function BP_ControlledCamera.BP_ControlledCamera_C.Created Button__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UW_CamControlButton_C*            Cam_Button                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::Created_Button__DelegateSignature(class UW_CamControlButton_C* Cam_Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Created Button__DelegateSignature");

	Params::BP_ControlledCamera_C_Created_Button__DelegateSignature Parms{};

	Parms.Cam_Button = Cam_Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.ExecuteUbergraph_BP_ControlledCamera
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::ExecuteUbergraph_BP_ControlledCamera(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "ExecuteUbergraph_BP_ControlledCamera");

	Params::BP_ControlledCamera_C_ExecuteUbergraph_BP_ControlledCamera Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Disable Cam
// (BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Disable_Cam()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Disable Cam");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.K2_OnEndViewTarget
// (Event, Public, BlueprintEvent)
// Parameters:
// class APlayerController*                PC                                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::K2_OnEndViewTarget(class APlayerController* PC)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "K2_OnEndViewTarget");

	Params::BP_ControlledCamera_C_K2_OnEndViewTarget Parms{};

	Parms.PC = PC;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.K2_OnBecomeViewTarget
// (Event, Public, BlueprintEvent)
// Parameters:
// class APlayerController*                PC                                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::K2_OnBecomeViewTarget(class APlayerController* PC)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "K2_OnBecomeViewTarget");

	Params::BP_ControlledCamera_C_K2_OnBecomeViewTarget Parms{};

	Parms.PC = PC;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Toggle View
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Active                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_ControlledCamera_C::Toggle_View(bool Active)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Toggle View");

	Params::BP_ControlledCamera_C_Toggle_View Parms{};

	Parms.Active = Active;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_ControlledCamera_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.ReceiveTick
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   DeltaSeconds                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::ReceiveTick(float DeltaSeconds)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "ReceiveTick");

	Params::BP_ControlledCamera_C_ReceiveTick Parms{};

	Parms.DeltaSeconds = DeltaSeconds;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpAxisEvt_MoveRight_K2Node_InputAxisEvent_1
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpAxisEvt_MoveRight_K2Node_InputAxisEvent_1(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpAxisEvt_MoveRight_K2Node_InputAxisEvent_1");

	Params::BP_ControlledCamera_C_InpAxisEvt_MoveRight_K2Node_InputAxisEvent_1 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0
// (BlueprintEvent)
// Parameters:
// float                                   AxisValue                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0(float AxisValue)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0");

	Params::BP_ControlledCamera_C_InpAxisEvt_MoveForward_K2Node_InputAxisEvent_0 Parms{};

	Parms.AxisValue = AxisValue;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpActEvt_Interact_K2Node_InputActionEvent_0
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpActEvt_Interact_K2Node_InputActionEvent_0(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpActEvt_Interact_K2Node_InputActionEvent_0");

	Params::BP_ControlledCamera_C_InpActEvt_Interact_K2Node_InputActionEvent_0 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpActEvt_ToggleStabilization_K2Node_InputActionEvent_1
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpActEvt_ToggleStabilization_K2Node_InputActionEvent_1(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpActEvt_ToggleStabilization_K2Node_InputActionEvent_1");

	Params::BP_ControlledCamera_C_InpActEvt_ToggleStabilization_K2Node_InputActionEvent_1 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpActEvt_Sprint_K2Node_InputActionEvent_2
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpActEvt_Sprint_K2Node_InputActionEvent_2(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpActEvt_Sprint_K2Node_InputActionEvent_2");

	Params::BP_ControlledCamera_C_InpActEvt_Sprint_K2Node_InputActionEvent_2 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpActEvt_Sprint_K2Node_InputActionEvent_3
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpActEvt_Sprint_K2Node_InputActionEvent_3(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpActEvt_Sprint_K2Node_InputActionEvent_3");

	Params::BP_ControlledCamera_C_InpActEvt_Sprint_K2Node_InputActionEvent_3 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.InpActEvt_LeanLeft_K2Node_InputActionEvent_4
// (BlueprintEvent)
// Parameters:
// struct FKey                             Key                                                    (BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)

void ABP_ControlledCamera_C::InpActEvt_LeanLeft_K2Node_InputActionEvent_4(const struct FKey& Key)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "InpActEvt_LeanLeft_K2Node_InputActionEvent_4");

	Params::BP_ControlledCamera_C_InpActEvt_LeanLeft_K2Node_InputActionEvent_4 Parms{};

	Parms.Key = std::move(Key);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Add Zoom Delta
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Add_Zoom_Delta()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Add Zoom Delta");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Add Camera Movement
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   X_Delta                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   Y_Delta                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_ControlledCamera_C::Add_Camera_Movement(float X_Delta, float Y_Delta)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Add Camera Movement");

	Params::BP_ControlledCamera_C_Add_Camera_Movement Parms{};

	Parms.X_Delta = X_Delta;
	Parms.Y_Delta = Y_Delta;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Clamp Camera Rotation
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Clamp_Camera_Rotation()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Clamp Camera Rotation");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Update Zoom
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Update_Zoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Update Zoom");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Find Vehicle
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Found_Vehicle                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_ControlledCamera_C::Find_Vehicle(bool* Found_Vehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Find Vehicle");

	Params::BP_ControlledCamera_C_Find_Vehicle Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Found_Vehicle != nullptr)
		*Found_Vehicle = Parms.Found_Vehicle;
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Update Follow
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Update_Follow()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Update Follow");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Create Stabilisation Point
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Create_Stabilisation_Point()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Create Stabilisation Point");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Check Soldier Wound
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Check_Soldier_Wound()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Check Soldier Wound");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Init Camera
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void ABP_ControlledCamera_C::Init_Camera()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Init Camera");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_ControlledCamera.BP_ControlledCamera_C.Can Become View Target
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Can_View                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_ControlledCamera_C::Can_Become_View_Target(bool* Can_View)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_ControlledCamera_C", "Can Become View Target");

	Params::BP_ControlledCamera_C_Can_Become_View_Target Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Can_View != nullptr)
		*Can_View = Parms.Can_View;
}

}
