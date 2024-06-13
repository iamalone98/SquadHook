#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_StanceState

#include "Basic.hpp"

#include "UMG_StanceState_classes.hpp"
#include "UMG_StanceState_parameters.hpp"


namespace SDK
{

// Function UMG_StanceState.UMG_StanceState_C.ExecuteUbergraph_UMG_StanceState
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_StanceState_C::ExecuteUbergraph_UMG_StanceState(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "ExecuteUbergraph_UMG_StanceState");

	Params::UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_StanceState.UMG_StanceState_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_StanceState_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_StanceState.UMG_StanceState_C.Update Stance Visibility
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USaveData_UI_C*                   Data                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_StanceState_C::Update_Stance_Visibility(class USaveData_UI_C* Data)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "Update Stance Visibility");

	Params::UMG_StanceState_C_Update_Stance_Visibility Parms{};

	Parms.Data = Data;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_StanceState.UMG_StanceState_C.UpdateStanceState
// (BlueprintCallable, BlueprintEvent)

void UUMG_StanceState_C::UpdateStanceState()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "UpdateStanceState");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_StanceState.UMG_StanceState_C.UpdateStance
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_StanceState_C::UpdateStance(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "UpdateStance");

	Params::UMG_StanceState_C_UpdateStance Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_StanceState.UMG_StanceState_C.UpdateLean
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_StanceState_C::UpdateLean(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "UpdateLean");

	Params::UMG_StanceState_C_UpdateLean Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_StanceState.UMG_StanceState_C.UpdateBleeding
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_StanceState_C::UpdateBleeding(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_StanceState_C", "UpdateBleeding");

	Params::UMG_StanceState_C_UpdateBleeding Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}

}
