#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Library_SquadUI

#include "Basic.hpp"

#include "Library_SquadUI_classes.hpp"
#include "Library_SquadUI_parameters.hpp"


namespace SDK
{

// Function Library_SquadUI.Library_SquadUI_C.Get UI Save Data
// (Static, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USaveData_UI_C*                   UI_Save_Data                                           (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ULibrary_SquadUI_C::Get_UI_Save_Data(class UObject* __WorldContext, class USaveData_UI_C** UI_Save_Data)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "Get UI Save Data");

	Params::Library_SquadUI_C_Get_UI_Save_Data Parms{};

	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	if (UI_Save_Data != nullptr)
		*UI_Save_Data = Parms.UI_Save_Data;
}


// Function Library_SquadUI.Library_SquadUI_C.Save UI Save Data
// (Static, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USaveData_UI_C*                   SaveGameObject                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ULibrary_SquadUI_C::Save_UI_Save_Data(class USaveData_UI_C* SaveGameObject, class UObject* __WorldContext)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "Save UI Save Data");

	Params::Library_SquadUI_C_Save_UI_Save_Data Parms{};

	Parms.SaveGameObject = SaveGameObject;
	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);
}


// Function Library_SquadUI.Library_SquadUI_C.Get SQHUD Colors
// (Static, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQColorsDataAsset*               ColorsDataAsset                                        (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ULibrary_SquadUI_C::Get_SQHUD_Colors(class UObject* __WorldContext, class USQColorsDataAsset** ColorsDataAsset)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "Get SQHUD Colors");

	Params::Library_SquadUI_C_Get_SQHUD_Colors Parms{};

	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	if (ColorsDataAsset != nullptr)
		*ColorsDataAsset = Parms.ColorsDataAsset;
}


// Function Library_SquadUI.Library_SquadUI_C.Add Notification
// (Static, Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (BlueprintVisible, BlueprintReadOnly, Parm)
// ESQNotificationTypes                    Type                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UTexture2D*                       Custom_Icon                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FLinearColor                     CustomIconColor                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    PreventRepetition                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ULibrary_SquadUI_C::Add_Notification(const class FText& Text, ESQNotificationTypes Type, class UTexture2D* Custom_Icon, const struct FLinearColor& CustomIconColor, bool PreventRepetition, class UObject* __WorldContext)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "Add Notification");

	Params::Library_SquadUI_C_Add_Notification Parms{};

	Parms.Text = std::move(Text);
	Parms.Type = Type;
	Parms.Custom_Icon = Custom_Icon;
	Parms.CustomIconColor = std::move(CustomIconColor);
	Parms.PreventRepetition = PreventRepetition;
	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);
}


// Function Library_SquadUI.Library_SquadUI_C.GetShortName
// (Static, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FName                             InputPin                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FText                             Short_Name                                             (Parm, OutParm)

void ULibrary_SquadUI_C::GetShortName(class FName InputPin, class UObject* __WorldContext, class FText* Short_Name)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "GetShortName");

	Params::Library_SquadUI_C_GetShortName Parms{};

	Parms.InputPin = InputPin;
	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	if (Short_Name != nullptr)
		*Short_Name = std::move(Parms.Short_Name);
}


// Function Library_SquadUI.Library_SquadUI_C.GetMicrophoneVolume
// (Static, Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// EMicrophoneVolume                       DiscreteVolume                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ULibrary_SquadUI_C::GetMicrophoneVolume(class UObject* __WorldContext, EMicrophoneVolume* DiscreteVolume)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("Library_SquadUI_C", "GetMicrophoneVolume");

	Params::Library_SquadUI_C_GetMicrophoneVolume Parms{};

	Parms.__WorldContext = __WorldContext;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	if (DiscreteVolume != nullptr)
		*DiscreteVolume = Parms.DiscreteVolume;
}


// Function Library_SquadUI.Library_SquadUI_C.ParseKeybind
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FString                           InString                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
// class UObject*                          __WorldContext                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FText                             Short_Name                                             (Parm, OutParm)

void ULibrary_SquadUI_C::ParseKeybind(const class FString& InString, class UObject* __WorldContext, class FText* Short_Name)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Library_SquadUI_C", "ParseKeybind");

	Params::Library_SquadUI_C_ParseKeybind Parms{};

	Parms.InString = std::move(InString);
	Parms.__WorldContext = __WorldContext;

	UObject::ProcessEvent(Func, &Parms);

	if (Short_Name != nullptr)
		*Short_Name = std::move(Parms.Short_Name);
}

}
