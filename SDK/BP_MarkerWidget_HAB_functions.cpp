#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_HAB

#include "Basic.hpp"

#include "BP_MarkerWidget_HAB_classes.hpp"
#include "BP_MarkerWidget_HAB_parameters.hpp"


namespace SDK
{

// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.ExecuteUbergraph_BP_MarkerWidget_HAB
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_HAB_C::ExecuteUbergraph_BP_MarkerWidget_HAB(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "ExecuteUbergraph_BP_MarkerWidget_HAB");

	Params::BP_MarkerWidget_HAB_C_ExecuteUbergraph_BP_MarkerWidget_HAB Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.UpdateStateEvent
// (BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_HAB_C::UpdateStateEvent()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "UpdateStateEvent");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MarkerWidget_HAB_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.UpdateSelectSpawnVisibility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_HAB_C::UpdateSelectSpawnVisibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "UpdateSelectSpawnVisibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.OnMouseButtonDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MarkerWidget_HAB_C::OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "OnMouseButtonDown");

	Params::BP_MarkerWidget_HAB_C_OnMouseButtonDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.SelectSpawn
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Commit                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_HAB_C::SelectSpawn(bool Commit)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "SelectSpawn");

	Params::BP_MarkerWidget_HAB_C_SelectSpawn Parms{};

	Parms.Commit = Commit;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.OnMouseButtonDoubleClick
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        InMyGeometry                                           (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    InMouseEvent                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MarkerWidget_HAB_C::OnMouseButtonDoubleClick(const struct FGeometry& InMyGeometry, const struct FPointerEvent& InMouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "OnMouseButtonDoubleClick");

	Params::BP_MarkerWidget_HAB_C_OnMouseButtonDoubleClick Parms{};

	Parms.InMyGeometry = std::move(InMyGeometry);
	Parms.InMouseEvent = std::move(InMouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.UpdateSpawnBrush
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FSlateBrush                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FSlateBrush UBP_MarkerWidget_HAB_C::UpdateSpawnBrush()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "UpdateSpawnBrush");

	Params::BP_MarkerWidget_HAB_C_UpdateSpawnBrush Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.UnselectSpawn
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_HAB_C::UnselectSpawn()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "UnselectSpawn");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.IsSelected
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// bool                                    Selected                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_HAB_C::IsSelected(bool* Selected) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "IsSelected");

	Params::BP_MarkerWidget_HAB_C_IsSelected Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Selected != nullptr)
		*Selected = Parms.Selected;
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.GetHAB
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ABP_Deployable_Hab_C*             HAB                                                    (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_HAB_C::GetHAB(class ABP_Deployable_Hab_C** HAB) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "GetHAB");

	Params::BP_MarkerWidget_HAB_C_GetHAB Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (HAB != nullptr)
		*HAB = Parms.HAB;
}


// Function BP_MarkerWidget_HAB.BP_MarkerWidget_HAB_C.GetSpawn
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQGameSpawn*                     Spawn                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_HAB_C::GetSpawn(class ASQGameSpawn** Spawn) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_HAB_C", "GetSpawn");

	Params::BP_MarkerWidget_HAB_C_GetSpawn Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Spawn != nullptr)
		*Spawn = Parms.Spawn;
}

}
