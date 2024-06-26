#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_FTUESplashScreen

#include "Basic.hpp"

#include "W_FTUESplashScreen_classes.hpp"
#include "W_FTUESplashScreen_parameters.hpp"


namespace SDK
{

// Function W_FTUESplashScreen.W_FTUESplashScreen_C.OnSplashScreenClosed__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UW_FTUESplashScreen_C::OnSplashScreenClosed__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FTUESplashScreen_C", "OnSplashScreenClosed__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_FTUESplashScreen.W_FTUESplashScreen_C.ExecuteUbergraph_W_FTUESplashScreen
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_FTUESplashScreen_C::ExecuteUbergraph_W_FTUESplashScreen(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FTUESplashScreen_C", "ExecuteUbergraph_W_FTUESplashScreen");

	Params::W_FTUESplashScreen_C_ExecuteUbergraph_W_FTUESplashScreen Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_FTUESplashScreen.W_FTUESplashScreen_C.BndEvt__W_PrivacyPolicy_Close_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UW_MainMenuButton_C*              Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_FTUESplashScreen_C::BndEvt__W_PrivacyPolicy_Close_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature(bool bSelected, class UW_MainMenuButton_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FTUESplashScreen_C", "BndEvt__W_PrivacyPolicy_Close_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature");

	Params::W_FTUESplashScreen_C_BndEvt__W_PrivacyPolicy_Close_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}

}

