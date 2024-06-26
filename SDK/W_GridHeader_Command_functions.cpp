#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridHeader_Command

#include "Basic.hpp"

#include "W_GridHeader_Command_classes.hpp"
#include "W_GridHeader_Command_parameters.hpp"


namespace SDK
{

// Function W_GridHeader_Command.W_GridHeader_Command_C.ExecuteUbergraph_W_GridHeader_Command
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_GridHeader_Command_C::ExecuteUbergraph_W_GridHeader_Command(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_Command_C", "ExecuteUbergraph_W_GridHeader_Command");

	Params::W_GridHeader_Command_C_ExecuteUbergraph_W_GridHeader_Command Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_GridHeader_Command.W_GridHeader_Command_C.Construct Categories
// (Public, BlueprintCallable, BlueprintEvent)

void UW_GridHeader_Command_C::Construct_Categories()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_Command_C", "Construct Categories");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_GridHeader_Command.W_GridHeader_Command_C.Construct Buttons
// (BlueprintCallable, BlueprintEvent)

void UW_GridHeader_Command_C::Construct_Buttons()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_GridHeader_Command_C", "Construct Buttons");

	UObject::ProcessEvent(Func, nullptr);
}

}

