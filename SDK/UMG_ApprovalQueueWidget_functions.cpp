#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_ApprovalQueueWidget

#include "Basic.hpp"

#include "UMG_ApprovalQueueWidget_classes.hpp"
#include "UMG_ApprovalQueueWidget_parameters.hpp"


namespace SDK
{

// Function UMG_ApprovalQueueWidget.UMG_ApprovalQueueWidget_C.ExecuteUbergraph_UMG_ApprovalQueueWidget
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_ApprovalQueueWidget_C::ExecuteUbergraph_UMG_ApprovalQueueWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ApprovalQueueWidget_C", "ExecuteUbergraph_UMG_ApprovalQueueWidget");

	Params::UMG_ApprovalQueueWidget_C_ExecuteUbergraph_UMG_ApprovalQueueWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_ApprovalQueueWidget.UMG_ApprovalQueueWidget_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_ApprovalQueueWidget_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_ApprovalQueueWidget_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}

