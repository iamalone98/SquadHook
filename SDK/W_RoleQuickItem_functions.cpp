#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RoleQuickItem

#include "Basic.hpp"

#include "W_RoleQuickItem_classes.hpp"
#include "W_RoleQuickItem_parameters.hpp"


namespace SDK
{

// Function W_RoleQuickItem.W_RoleQuickItem_C.ExecuteUbergraph_W_RoleQuickItem
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleQuickItem_C::ExecuteUbergraph_W_RoleQuickItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "ExecuteUbergraph_W_RoleQuickItem");

	Params::W_RoleQuickItem_C_ExecuteUbergraph_W_RoleQuickItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.BndEvt__Button_Role_K2Node_ComponentBoundEvent_27_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void UW_RoleQuickItem_C::BndEvt__Button_Role_K2Node_ComponentBoundEvent_27_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "BndEvt__Button_Role_K2Node_ComponentBoundEvent_27_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.UpdateExpositionQuick
// (Public, BlueprintCallable, BlueprintEvent)

void UW_RoleQuickItem_C::UpdateExpositionQuick()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "UpdateExpositionQuick");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.GetRoleToolTipWidget
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidget*                          ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UWidget* UW_RoleQuickItem_C::GetRoleToolTipWidget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "GetRoleToolTipWidget");

	Params::W_RoleQuickItem_C_GetRoleToolTipWidget Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.SetupExpositionQuick
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_RoleQuickItem_C::SetupExpositionQuick()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "SetupExpositionQuick");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.SetupExposition
// (Public, BlueprintCallable, BlueprintEvent)

void UW_RoleQuickItem_C::SetupExposition()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "SetupExposition");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_RoleQuickItem_C::BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_RoleQuickItem_C::BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "BndEvt__Button_SquadMember_K2Node_ComponentBoundEvent_0_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.UpdateExposition
// (Public, BlueprintCallable, BlueprintEvent)

void UW_RoleQuickItem_C::UpdateExposition()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "UpdateExposition");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleQuickItem.W_RoleQuickItem_C.IsButtonHovered
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Is_Hovered                                             (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_RoleQuickItem_C::IsButtonHovered(bool* Is_Hovered)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleQuickItem_C", "IsButtonHovered");

	Params::W_RoleQuickItem_C_IsButtonHovered Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Is_Hovered != nullptr)
		*Is_Hovered = Parms.Is_Hovered;
}

}

