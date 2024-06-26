#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ObjectEntry

#include "Basic.hpp"

#include "W_ObjectEntry_classes.hpp"
#include "W_ObjectEntry_parameters.hpp"


namespace SDK
{

// Function W_ObjectEntry.W_ObjectEntry_C.ExecuteUbergraph_W_ObjectEntry
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ObjectEntry_C::ExecuteUbergraph_W_ObjectEntry(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "ExecuteUbergraph_W_ObjectEntry");

	Params::W_ObjectEntry_C_ExecuteUbergraph_W_ObjectEntry Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ObjectEntry.W_ObjectEntry_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ObjectEntry_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "PreConstruct");

	Params::W_ObjectEntry_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ObjectEntry.W_ObjectEntry_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_ObjectEntry_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ObjectEntry.W_ObjectEntry_C.BP_OnItemSelectionChanged
// (Event, Protected, BlueprintEvent)
// Parameters:
// bool                                    bIsSelected                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ObjectEntry_C::BP_OnItemSelectionChanged(bool bIsSelected)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "BP_OnItemSelectionChanged");

	Params::W_ObjectEntry_C_BP_OnItemSelectionChanged Parms{};

	Parms.bIsSelected = bIsSelected;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ObjectEntry.W_ObjectEntry_C.OnListItemObjectSet
// (Event, Protected, BlueprintEvent)
// Parameters:
// class UObject*                          ListItemObject                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ObjectEntry_C::OnListItemObjectSet(class UObject* ListItemObject)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "OnListItemObjectSet");

	Params::W_ObjectEntry_C_OnListItemObjectSet Parms{};

	Parms.ListItemObject = ListItemObject;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ObjectEntry.W_ObjectEntry_C.BP_OnItemExpansionChanged
// (Event, Protected, BlueprintEvent)
// Parameters:
// bool                                    bIsExpanded                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ObjectEntry_C::BP_OnItemExpansionChanged(bool bIsExpanded)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "BP_OnItemExpansionChanged");

	Params::W_ObjectEntry_C_BP_OnItemExpansionChanged Parms{};

	Parms.bIsExpanded = bIsExpanded;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ObjectEntry.W_ObjectEntry_C.BP_OnEntryReleased
// (Event, Protected, BlueprintEvent)

void UW_ObjectEntry_C::BP_OnEntryReleased()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "BP_OnEntryReleased");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_ObjectEntry.W_ObjectEntry_C.UpdateHightlight
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    IsHightlighted                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ObjectEntry_C::UpdateHightlight(bool IsHightlighted)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ObjectEntry_C", "UpdateHightlight");

	Params::W_ObjectEntry_C_UpdateHightlight Parms{};

	Parms.IsHightlighted = IsHightlighted;

	UObject::ProcessEvent(Func, &Parms);
}

}

