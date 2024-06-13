#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ServerTag

#include "Basic.hpp"

#include "ServerTag_classes.hpp"
#include "ServerTag_parameters.hpp"


namespace SDK
{

// Function ServerTag.ServerTag_C.Update Visual
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Display                                                (BlueprintVisible, BlueprintReadOnly, Parm)
// struct FLinearColor                     Color                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UServerTag_C::Update_Visual(const class FText& Display, const struct FLinearColor& Color)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("ServerTag_C", "Update Visual");

	Params::ServerTag_C_Update_Visual Parms{};

	Parms.Display = std::move(Display);
	Parms.Color = std::move(Color);

	UObject::ProcessEvent(Func, &Parms);
}


// Function ServerTag.ServerTag_C.ChangeCommaVisibility
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    bShow                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UServerTag_C::ChangeCommaVisibility(bool bShow)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("ServerTag_C", "ChangeCommaVisibility");

	Params::ServerTag_C_ChangeCommaVisibility Parms{};

	Parms.bShow = bShow;

	UObject::ProcessEvent(Func, &Parms);
}


// Function ServerTag.ServerTag_C.SetDisplayText
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (BlueprintVisible, BlueprintReadOnly, Parm)

void UServerTag_C::SetDisplayText(const class FText& Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("ServerTag_C", "SetDisplayText");

	Params::ServerTag_C_SetDisplayText Parms{};

	Parms.Text = std::move(Text);

	UObject::ProcessEvent(Func, &Parms);
}


// Function ServerTag.ServerTag_C.GetDisplayText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class FText                             Text                                                   (Parm, OutParm)

void UServerTag_C::GetDisplayText(class FText* Text) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("ServerTag_C", "GetDisplayText");

	Params::ServerTag_C_GetDisplayText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Text != nullptr)
		*Text = std::move(Parms.Text);
}

}

