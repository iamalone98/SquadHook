#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ModDownloadWindow

#include "Basic.hpp"

#include "W_ModDownloadWindow_classes.hpp"
#include "W_ModDownloadWindow_parameters.hpp"


namespace SDK
{

// Function W_ModDownloadWindow.W_ModDownloadWindow_C.DownloadingFinished__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UW_ModDownloadWindow_C::DownloadingFinished__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "DownloadingFinished__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.ExecuteUbergraph_W_ModDownloadWindow
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ModDownloadWindow_C::ExecuteUbergraph_W_ModDownloadWindow(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "ExecuteUbergraph_W_ModDownloadWindow");

	Params::W_ModDownloadWindow_C_ExecuteUbergraph_W_ModDownloadWindow Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_ModDownloadWindow_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ModDownloadWindow_C::BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature");

	Params::W_ModDownloadWindow_C_BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.BndEvt__Button_Download_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ModDownloadWindow_C::BndEvt__Button_Download_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "BndEvt__Button_Download_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");

	Params::W_ModDownloadWindow_C_BndEvt__Button_Download_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ModDownloadWindow_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Tick");

	Params::W_ModDownloadWindow_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Is Finished Loading
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Result                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ModDownloadWindow_C::Is_Finished_Loading(bool* Result)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Is Finished Loading");

	Params::W_ModDownloadWindow_C_Is_Finished_Loading Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Result != nullptr)
		*Result = Parms.Result;
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Is Download Successful
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Result                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ModDownloadWindow_C::Is_Download_Successful(bool* Result)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Is Download Successful");

	Params::W_ModDownloadWindow_C_Is_Download_Successful Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Result != nullptr)
		*Result = Parms.Result;
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Update Mod Download Window
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_ModDownloadWindow_C::Update_Mod_Download_Window()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Update Mod Download Window");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Init Mod Window
// (Public, BlueprintCallable, BlueprintEvent)

void UW_ModDownloadWindow_C::Init_Mod_Window()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Init Mod Window");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ModDownloadWindow.W_ModDownloadWindow_C.Is Download Aborted
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Result                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ModDownloadWindow_C::Is_Download_Aborted(bool* Result)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ModDownloadWindow_C", "Is Download Aborted");

	Params::W_ModDownloadWindow_C_Is_Download_Aborted Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Result != nullptr)
		*Result = Parms.Result;
}

}
