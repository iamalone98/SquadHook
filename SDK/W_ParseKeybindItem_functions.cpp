#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ParseKeybindItem

#include "Basic.hpp"

#include "W_ParseKeybindItem_classes.hpp"
#include "W_ParseKeybindItem_parameters.hpp"


namespace SDK
{

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.ExecuteUbergraph_W_ParseKeybindItem
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ParseKeybindItem_C::ExecuteUbergraph_W_ParseKeybindItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ParseKeybindItem_C", "ExecuteUbergraph_W_ParseKeybindItem");

	Params::W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ParseKeybindItem.W_ParseKeybindItem_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_ParseKeybindItem_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ParseKeybindItem_C", "PreConstruct");

	Params::W_ParseKeybindItem_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_ParseKeybindItem_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ParseKeybindItem_C", "Tick");

	Params::W_ParseKeybindItem_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Parse Keybind
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FString                           InString                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
// class FText                             Short_Name                                             (Parm, OutParm)

void UW_ParseKeybindItem_C::Parse_Keybind(const class FString& InString, class FText* Short_Name)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ParseKeybindItem_C", "Parse Keybind");

	Params::W_ParseKeybindItem_C_Parse_Keybind Parms{};

	Parms.InString = std::move(InString);

	UObject::ProcessEvent(Func, &Parms);

	if (Short_Name != nullptr)
		*Short_Name = std::move(Parms.Short_Name);
}


// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Get Short Name
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FName                             Action_Name                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FText                             Short_Name                                             (Parm, OutParm)

void UW_ParseKeybindItem_C::Get_Short_Name(class FName Action_Name, class FText* Short_Name)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_ParseKeybindItem_C", "Get Short Name");

	Params::W_ParseKeybindItem_C_Get_Short_Name Parms{};

	Parms.Action_Name = Action_Name;

	UObject::ProcessEvent(Func, &Parms);

	if (Short_Name != nullptr)
		*Short_Name = std::move(Parms.Short_Name);
}

}
