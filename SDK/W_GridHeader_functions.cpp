#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridHeader

#include "Basic.hpp"

#include "W_GridHeader_classes.hpp"
#include "W_GridHeader_parameters.hpp"


namespace SDK
{

// Function W_GridHeader.W_GridHeader_C.ExecuteUbergraph_W_GridHeader
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_GridHeader_C::ExecuteUbergraph_W_GridHeader(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "ExecuteUbergraph_W_GridHeader");

	Params::W_GridHeader_C_ExecuteUbergraph_W_GridHeader Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_GridHeader.W_GridHeader_C.Construct Buttons
// (BlueprintCallable, BlueprintEvent)

void UW_GridHeader_C::Construct_Buttons()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Construct Buttons");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_GridHeader.W_GridHeader_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_GridHeader_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_GridHeader.W_GridHeader_C.Set Viewport Position
// (Public, BlueprintCallable, BlueprintEvent)

void UW_GridHeader_C::Set_Viewport_Position()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Set Viewport Position");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_GridHeader.W_GridHeader_C.Set Buttons Visibility
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Visible                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_GridHeader_C::Set_Buttons_Visibility(bool Visible)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Set Buttons Visibility");

	Params::W_GridHeader_C_Set_Buttons_Visibility Parms{};

	Parms.Visible = Visible;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_GridHeader.W_GridHeader_C.Get Fireteam ID
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// int32                                   ID                                                     (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_GridHeader_C::Get_Fireteam_ID(int32* ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Get Fireteam ID");

	Params::W_GridHeader_C_Get_Fireteam_ID Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (ID != nullptr)
		*ID = Parms.ID;
}


// Function W_GridHeader.W_GridHeader_C.Get Squad ID
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// int32                                   ID                                                     (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_GridHeader_C::Get_Squad_ID(int32* ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_C", "Get Squad ID");

	Params::W_GridHeader_C_Get_Squad_ID Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (ID != nullptr)
		*ID = Parms.ID;
}

}
