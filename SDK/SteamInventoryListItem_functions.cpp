#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SteamInventoryListItem

#include "Basic.hpp"

#include "SteamInventoryListItem_classes.hpp"
#include "SteamInventoryListItem_parameters.hpp"


namespace SDK
{

// Function SteamInventoryListItem.SteamInventoryListItem_C.ExecuteUbergraph_SteamInventoryListItem
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USteamInventoryListItem_C::ExecuteUbergraph_SteamInventoryListItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "ExecuteUbergraph_SteamInventoryListItem");

	Params::SteamInventoryListItem_C_ExecuteUbergraph_SteamInventoryListItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.UpdateTickBox
// (BlueprintCallable, BlueprintEvent)

void USteamInventoryListItem_C::UpdateTickBox()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "UpdateTickBox");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.OnStateChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQSteamItem*                     ChangedItem                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USteamInventoryListItem_C::OnStateChanged(class USQSteamItem* ChangedItem)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "OnStateChanged");

	Params::SteamInventoryListItem_C_OnStateChanged Parms{};

	Parms.ChangedItem = ChangedItem;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.BndEvt__InvisButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature
// (BlueprintEvent)

void USteamInventoryListItem_C::BndEvt__InvisButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "BndEvt__InvisButton_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.OnListItemObjectSet
// (Event, Protected, BlueprintEvent)
// Parameters:
// class UObject*                          ListItemObject                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USteamInventoryListItem_C::OnListItemObjectSet(class UObject* ListItemObject)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "OnListItemObjectSet");

	Params::SteamInventoryListItem_C_OnListItemObjectSet Parms{};

	Parms.ListItemObject = ListItemObject;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.BP_OnItemSelectionChanged
// (Event, Protected, BlueprintEvent)
// Parameters:
// bool                                    bIsSelected                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USteamInventoryListItem_C::BP_OnItemSelectionChanged(bool bIsSelected)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "BP_OnItemSelectionChanged");

	Params::SteamInventoryListItem_C_BP_OnItemSelectionChanged Parms{};

	Parms.bIsSelected = bIsSelected;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.BP_OnItemExpansionChanged
// (Event, Protected, BlueprintEvent)
// Parameters:
// bool                                    bIsExpanded                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void USteamInventoryListItem_C::BP_OnItemExpansionChanged(bool bIsExpanded)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "BP_OnItemExpansionChanged");

	Params::SteamInventoryListItem_C_BP_OnItemExpansionChanged Parms{};

	Parms.bIsExpanded = bIsExpanded;

	UObject::ProcessEvent(Func, &Parms);
}


// Function SteamInventoryListItem.SteamInventoryListItem_C.BP_OnEntryReleased
// (Event, Protected, BlueprintEvent)

void USteamInventoryListItem_C::BP_OnEntryReleased()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SteamInventoryListItem_C", "BP_OnEntryReleased");

	UObject::ProcessEvent(Func, nullptr);
}

}
