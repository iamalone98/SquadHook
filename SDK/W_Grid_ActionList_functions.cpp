#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Grid_ActionList

#include "Basic.hpp"

#include "W_Grid_ActionList_classes.hpp"
#include "W_Grid_ActionList_parameters.hpp"


namespace SDK
{

// Function W_Grid_ActionList.W_Grid_ActionList_C.Closed__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UW_Grid_ActionList_C::Closed__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Closed__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.ExecuteUbergraph_W_Grid_ActionList
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Grid_ActionList_C::ExecuteUbergraph_W_Grid_ActionList(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "ExecuteUbergraph_W_Grid_ActionList");

	Params::W_Grid_ActionList_C_ExecuteUbergraph_W_Grid_ActionList Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Populate List
// (BlueprintCallable, BlueprintEvent)

void UW_Grid_ActionList_C::Populate_List()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Populate List");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_Grid_ActionList_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Close
// (BlueprintCallable, BlueprintEvent)

void UW_Grid_ActionList_C::Close()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Close");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_Grid_ActionList_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "PreConstruct");

	Params::W_Grid_ActionList_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Grid_ActionList_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Tick");

	Params::W_Grid_ActionList_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Get Fireteam ID
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// int32                                   ID                                                     (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Grid_ActionList_C::Get_Fireteam_ID(int32* ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Get Fireteam ID");

	Params::W_Grid_ActionList_C_Get_Fireteam_ID Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (ID != nullptr)
		*ID = Parms.ID;
}


// Function W_Grid_ActionList.W_Grid_ActionList_C.Get Squad ID
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// int32                                   ID                                                     (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Grid_ActionList_C::Get_Squad_ID(int32* ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Grid_ActionList_C", "Get Squad ID");

	Params::W_Grid_ActionList_C_Get_Squad_ID Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (ID != nullptr)
		*ID = Parms.ID;
}

}

