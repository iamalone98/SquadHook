#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_BackpackRow

#include "Basic.hpp"

#include "W_BackpackRow_classes.hpp"
#include "W_BackpackRow_parameters.hpp"


namespace SDK
{

// Function W_BackpackRow.W_BackpackRow_C.ExecuteUbergraph_W_BackpackRow
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_BackpackRow_C::ExecuteUbergraph_W_BackpackRow(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BackpackRow_C", "ExecuteUbergraph_W_BackpackRow");

	Params::W_BackpackRow_C_ExecuteUbergraph_W_BackpackRow Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BackpackRow.W_BackpackRow_C.Update Details
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQEquipableItem*                 Item                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_BackpackRow_C::Update_Details(class ASQEquipableItem* Item)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BackpackRow_C", "Update Details");

	Params::W_BackpackRow_C_Update_Details Parms{};

	Parms.Item = Item;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_BackpackRow.W_BackpackRow_C.Set Items
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// TArray<class ASQEquipableItem*>         In_Array                                               (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// TArray<struct FSQInventoryData>         Param_Data_Array                                       (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)

void UW_BackpackRow_C::Set_Items(const TArray<class ASQEquipableItem*>& In_Array, const TArray<struct FSQInventoryData>& Param_Data_Array)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_BackpackRow_C", "Set Items");

	Params::W_BackpackRow_C_Set_Items Parms{};

	Parms.In_Array = std::move(In_Array);
	Parms.Param_Data_Array = std::move(Param_Data_Array);

	UObject::ProcessEvent(Func, &Parms);
}

}

