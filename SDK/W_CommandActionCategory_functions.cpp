#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandActionCategory

#include "Basic.hpp"

#include "W_CommandActionCategory_classes.hpp"
#include "W_CommandActionCategory_parameters.hpp"


namespace SDK
{

// Function W_CommandActionCategory.W_CommandActionCategory_C.ExecuteUbergraph_W_CommandActionCategory
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandActionCategory_C::ExecuteUbergraph_W_CommandActionCategory(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "ExecuteUbergraph_W_CommandActionCategory");

	Params::W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandActionCategory.W_CommandActionCategory_C.Init
// (BlueprintCallable, BlueprintEvent)

void UW_CommandActionCategory_C::Init()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "Init");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandActionCategory.W_CommandActionCategory_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_CommandActionCategory_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "Tick");

	Params::W_CommandActionCategory_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_CommandActionCategory.W_CommandActionCategory_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_CommandActionCategory_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandActionCategory.W_CommandActionCategory_C.Update Category
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_CommandActionCategory_C::Update_Category()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "Update Category");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_CommandActionCategory.W_CommandActionCategory_C.Check Interaction
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Locked                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_CommandActionCategory_C::Check_Interaction(bool* Locked)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_CommandActionCategory_C", "Check Interaction");

	Params::W_CommandActionCategory_C_Check_Interaction Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Locked != nullptr)
		*Locked = Parms.Locked;
}

}

