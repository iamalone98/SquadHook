#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Role_Inventory

#include "Basic.hpp"

#include "BP_Role_Inventory_classes.hpp"
#include "BP_Role_Inventory_parameters.hpp"


namespace SDK
{

// Function BP_Role_Inventory.BP_Role_Inventory_C.ExecuteUbergraph_BP_Role_Inventory
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_Role_Inventory_C::ExecuteUbergraph_BP_Role_Inventory(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "ExecuteUbergraph_BP_Role_Inventory");

	Params::BP_Role_Inventory_C_ExecuteUbergraph_BP_Role_Inventory Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Role_Inventory.BP_Role_Inventory_C.UpdateStateAndVisibilityEvent
// (BlueprintCallable, BlueprintEvent)

void UBP_Role_Inventory_C::UpdateStateAndVisibilityEvent()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "UpdateStateAndVisibilityEvent");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Role_Inventory.BP_Role_Inventory_C.PopulateInventoryUI
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_Role_Inventory_C::PopulateInventoryUI()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "PopulateInventoryUI");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Role_Inventory.BP_Role_Inventory_C.AddItemToInventory
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FSQInventoryData                 InventoryData                                          (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// int32                                   Param_Slot                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Offset                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_Role_Inventory_C::AddItemToInventory(const struct FSQInventoryData& InventoryData, int32 Param_Slot, int32 Offset)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "AddItemToInventory");

	Params::BP_Role_Inventory_C_AddItemToInventory Parms{};

	Parms.InventoryData = std::move(InventoryData);
	Parms.Param_Slot = Param_Slot;
	Parms.Offset = Offset;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Role_Inventory.BP_Role_Inventory_C.GetRulesetModifications
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_Role_Inventory_C::GetRulesetModifications()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "GetRulesetModifications");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Role_Inventory.BP_Role_Inventory_C.ClearWidget
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_Role_Inventory_C::ClearWidget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Role_Inventory_C", "ClearWidget");

	UObject::ProcessEvent(Func, nullptr);
}

}
