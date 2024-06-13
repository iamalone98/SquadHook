#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_RallyPoint

#include "Basic.hpp"

#include "BP_MarkerWidget_RallyPoint_classes.hpp"
#include "BP_MarkerWidget_RallyPoint_parameters.hpp"


namespace SDK
{

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.ExecuteUbergraph_BP_MarkerWidget_RallyPoint
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_RallyPoint_C::ExecuteUbergraph_BP_MarkerWidget_RallyPoint(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "ExecuteUbergraph_BP_MarkerWidget_RallyPoint");

	Params::BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateStateEvent
// (BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_RallyPoint_C::UpdateStateEvent()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "UpdateStateEvent");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_RallyPoint_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "Tick");

	Params::BP_MarkerWidget_RallyPoint_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MarkerWidget_RallyPoint_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateSquadIDText
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_RallyPoint_C::UpdateSquadIDText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "UpdateSquadIDText");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.OnMouseButtonDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MarkerWidget_RallyPoint_C::OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "OnMouseButtonDown");

	Params::BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateSelectVisibility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_RallyPoint_C::UpdateSelectVisibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "UpdateSelectVisibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.SelectSpawn
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Commit                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_RallyPoint_C::SelectSpawn(bool Commit)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "SelectSpawn");

	Params::BP_MarkerWidget_RallyPoint_C_SelectSpawn Parms{};

	Parms.Commit = Commit;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.OnMouseButtonDoubleClick
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        InMyGeometry                                           (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    InMouseEvent                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MarkerWidget_RallyPoint_C::OnMouseButtonDoubleClick(const struct FGeometry& InMyGeometry, const struct FPointerEvent& InMouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "OnMouseButtonDoubleClick");

	Params::BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick Parms{};

	Parms.InMyGeometry = std::move(InMyGeometry);
	Parms.InMouseEvent = std::move(InMouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateRallyPointBrush
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_RallyPoint_C::UpdateRallyPointBrush()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_RallyPoint_C", "UpdateRallyPointBrush");

	UObject::ProcessEvent(Func, nullptr);
}

}

