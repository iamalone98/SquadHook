#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_FloatingWidget

#include "Basic.hpp"

#include "W_FloatingWidget_classes.hpp"
#include "W_FloatingWidget_parameters.hpp"


namespace SDK
{

// Function W_FloatingWidget.W_FloatingWidget_C.ExecuteUbergraph_W_FloatingWidget
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_FloatingWidget_C::ExecuteUbergraph_W_FloatingWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FloatingWidget_C", "ExecuteUbergraph_W_FloatingWidget");

	Params::W_FloatingWidget_C_ExecuteUbergraph_W_FloatingWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_FloatingWidget.W_FloatingWidget_C.Remove floating widget
// (BlueprintCallable, BlueprintEvent)

void UW_FloatingWidget_C::Remove_floating_widget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FloatingWidget_C", "Remove floating widget");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_FloatingWidget.W_FloatingWidget_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_FloatingWidget_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FloatingWidget_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_FloatingWidget.W_FloatingWidget_C.On Map Mouse Down
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPointerEvent                    Mouse_Event                                            (BlueprintVisible, BlueprintReadOnly, Parm)
// struct FVector                          World_Location                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_FloatingWidget_C::On_Map_Mouse_Down(const struct FPointerEvent& Mouse_Event, const struct FVector& World_Location)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FloatingWidget_C", "On Map Mouse Down");

	Params::W_FloatingWidget_C_On_Map_Mouse_Down Parms{};

	Parms.Mouse_Event = std::move(Mouse_Event);
	Parms.World_Location = std::move(World_Location);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_FloatingWidget.W_FloatingWidget_C.Validate Action
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FPointerEvent                    Mouse_Event                                            (BlueprintVisible, BlueprintReadOnly, Parm)
// bool                                    Valid                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_FloatingWidget_C::Validate_Action(const struct FPointerEvent& Mouse_Event, bool* Valid)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_FloatingWidget_C", "Validate Action");

	Params::W_FloatingWidget_C_Validate_Action Parms{};

	Parms.Mouse_Event = std::move(Mouse_Event);

	UObject::ProcessEvent(Func, &Parms);

	if (Valid != nullptr)
		*Valid = Parms.Valid;
}

}
