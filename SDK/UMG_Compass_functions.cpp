#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Compass

#include "Basic.hpp"

#include "UMG_Compass_classes.hpp"
#include "UMG_Compass_parameters.hpp"


namespace SDK
{

// Function UMG_Compass.UMG_Compass_C.CheckVisibilityStatus_0__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UUMG_Compass_C::CheckVisibilityStatus_0__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "CheckVisibilityStatus_0__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_Compass.UMG_Compass_C.ExecuteUbergraph_UMG_Compass
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_Compass_C::ExecuteUbergraph_UMG_Compass(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "ExecuteUbergraph_UMG_Compass");

	Params::UMG_Compass_C_ExecuteUbergraph_UMG_Compass Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_Compass.UMG_Compass_C.OnUserSettingsChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQGameUserSettings*              UserSettings                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_Compass_C::OnUserSettingsChanged(const class USQGameUserSettings* UserSettings)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "OnUserSettingsChanged");

	Params::UMG_Compass_C_OnUserSettingsChanged Parms{};

	Parms.UserSettings = UserSettings;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_Compass.UMG_Compass_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_Compass_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "PreConstruct");

	Params::UMG_Compass_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_Compass.UMG_Compass_C.Set Compass Visibility
// (BlueprintCallable, BlueprintEvent)

void UUMG_Compass_C::Set_Compass_Visibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "Set Compass Visibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_Compass.UMG_Compass_C.BPInit
// (Event, Public, BlueprintEvent)

void UUMG_Compass_C::BPInit()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "BPInit");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_Compass.UMG_Compass_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_Compass_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_Compass.UMG_Compass_C.ChangeDisplayMode
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_bTopScreenView                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UUMG_Compass_C::ChangeDisplayMode(bool Param_bTopScreenView)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Compass_C", "ChangeDisplayMode");

	Params::UMG_Compass_C_ChangeDisplayMode Parms{};

	Parms.Param_bTopScreenView = Param_bTopScreenView;

	UObject::ProcessEvent(Func, &Parms);
}

}
