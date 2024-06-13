#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialRearmWidget

#include "Basic.hpp"

#include "RadialRearmWidget_classes.hpp"
#include "RadialRearmWidget_parameters.hpp"


namespace SDK
{

// Function RadialRearmWidget.RadialRearmWidget_C.ExecuteUbergraph_RadialRearmWidget
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialRearmWidget_C::ExecuteUbergraph_RadialRearmWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "ExecuteUbergraph_RadialRearmWidget");

	Params::RadialRearmWidget_C_ExecuteUbergraph_RadialRearmWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialRearmWidget.RadialRearmWidget_C.Destruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void URadialRearmWidget_C::Destruct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "Destruct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.InventoryUpdated
// (BlueprintCallable, BlueprintEvent)

void URadialRearmWidget_C::InventoryUpdated()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "InventoryUpdated");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.RecalculateCanClick
// (BlueprintCallable, BlueprintEvent)

void URadialRearmWidget_C::RecalculateCanClick()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "RecalculateCanClick");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.OnRightClicked
// (BlueprintCallable, BlueprintEvent)

void URadialRearmWidget_C::OnRightClicked()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "OnRightClicked");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.SetCenterWidget
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class URadialCenterRearmButton_C*       Param_CenterWidget                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialRearmWidget_C::SetCenterWidget(class URadialCenterRearmButton_C* Param_CenterWidget)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "SetCenterWidget");

	Params::RadialRearmWidget_C_SetCenterWidget Parms{};

	Parms.Param_CenterWidget = Param_CenterWidget;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialRearmWidget.RadialRearmWidget_C.AmmoRemainingUpdated
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   AmmoRemaining                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialRearmWidget_C::AmmoRemainingUpdated(float AmmoRemaining)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "AmmoRemainingUpdated");

	Params::RadialRearmWidget_C_AmmoRemainingUpdated Parms{};

	Parms.AmmoRemaining = AmmoRemaining;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialRearmWidget.RadialRearmWidget_C.UpdateRadialAngle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   UpdatedAngle                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialRearmWidget_C::UpdateRadialAngle(float UpdatedAngle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "UpdateRadialAngle");

	Params::RadialRearmWidget_C_UpdateRadialAngle Parms{};

	Parms.UpdatedAngle = UpdatedAngle;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialRearmWidget.RadialRearmWidget_C.OnHoverBegin
// (Event, Public, BlueprintCallable, BlueprintEvent)

void URadialRearmWidget_C::OnHoverBegin()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "OnHoverBegin");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.BPInit
// (Event, Public, BlueprintEvent)

void URadialRearmWidget_C::BPInit()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "BPInit");

	UObject::ProcessEvent(Func, nullptr);
}


// Function RadialRearmWidget.RadialRearmWidget_C.GetMagsToRearmText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText URadialRearmWidget_C::GetMagsToRearmText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "GetMagsToRearmText");

	Params::RadialRearmWidget_C_GetMagsToRearmText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function RadialRearmWidget.RadialRearmWidget_C.OnPreviewMouseButtonDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply URadialRearmWidget_C::OnPreviewMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "OnPreviewMouseButtonDown");

	Params::RadialRearmWidget_C_OnPreviewMouseButtonDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function RadialRearmWidget.RadialRearmWidget_C.OnMouseButtonDoubleClick
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        InMyGeometry                                           (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    InMouseEvent                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply URadialRearmWidget_C::OnMouseButtonDoubleClick(const struct FGeometry& InMyGeometry, const struct FPointerEvent& InMouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "OnMouseButtonDoubleClick");

	Params::RadialRearmWidget_C_OnMouseButtonDoubleClick Parms{};

	Parms.InMyGeometry = std::move(InMyGeometry);
	Parms.InMouseEvent = std::move(InMouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function RadialRearmWidget.RadialRearmWidget_C.UpdateBackgroundColors
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    CanClick                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    IsAmmoFull                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void URadialRearmWidget_C::UpdateBackgroundColors(bool CanClick, bool IsAmmoFull)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialRearmWidget_C", "UpdateBackgroundColors");

	Params::RadialRearmWidget_C_UpdateBackgroundColors Parms{};

	Parms.CanClick = CanClick;
	Parms.IsAmmoFull = IsAmmoFull;

	UObject::ProcessEvent(Func, &Parms);
}

}

