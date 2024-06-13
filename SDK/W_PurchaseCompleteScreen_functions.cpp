#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_PurchaseCompleteScreen

#include "Basic.hpp"

#include "W_PurchaseCompleteScreen_classes.hpp"
#include "W_PurchaseCompleteScreen_parameters.hpp"


namespace SDK
{

// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.OnClose__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UODKBazaarBundle*                 ClosedBundle                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_PurchaseCompleteScreen_C::OnClose__DelegateSignature(class UODKBazaarBundle* ClosedBundle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "OnClose__DelegateSignature");

	Params::W_PurchaseCompleteScreen_C_OnClose__DelegateSignature Parms{};

	Parms.ClosedBundle = ClosedBundle;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.OnGotoEquip__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UW_PurchaseCompleteScreen_C::OnGotoEquip__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "OnGotoEquip__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.ExecuteUbergraph_W_PurchaseCompleteScreen
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_PurchaseCompleteScreen_C::ExecuteUbergraph_W_PurchaseCompleteScreen(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "ExecuteUbergraph_W_PurchaseCompleteScreen");

	Params::W_PurchaseCompleteScreen_C_ExecuteUbergraph_W_PurchaseCompleteScreen Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_PurchaseCompleteScreen_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.BndEvt__EquipButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UW_PurchaseCompleteScreen_C::BndEvt__EquipButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "BndEvt__EquipButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_PurchaseCompleteScreen.W_PurchaseCompleteScreen_C.BndEvt__ContinueButton_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UW_PurchaseCompleteScreen_C::BndEvt__ContinueButton_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_PurchaseCompleteScreen_C", "BndEvt__ContinueButton_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}

}
