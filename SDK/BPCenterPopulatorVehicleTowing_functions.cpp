#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPCenterPopulatorVehicleTowing

#include "Basic.hpp"

#include "BPCenterPopulatorVehicleTowing_classes.hpp"
#include "BPCenterPopulatorVehicleTowing_parameters.hpp"


namespace SDK
{

// Function BPCenterPopulatorVehicleTowing.BPCenterPopulatorVehicleTowing_C.ExecuteUbergraph_BPCenterPopulatorVehicleTowing
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBPCenterPopulatorVehicleTowing_C::ExecuteUbergraph_BPCenterPopulatorVehicleTowing(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPCenterPopulatorVehicleTowing_C", "ExecuteUbergraph_BPCenterPopulatorVehicleTowing");

	Params::BPCenterPopulatorVehicleTowing_C_ExecuteUbergraph_BPCenterPopulatorVehicleTowing Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BPCenterPopulatorVehicleTowing.BPCenterPopulatorVehicleTowing_C.FinishWidgetSetup
// (Protected, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQUserWidget*                    Widget                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBaseRadialMenu_C*                RadialMenu                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBP_RadialItemModel_C*            ActionModel                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBPCenterPopulatorVehicleTowing_C::FinishWidgetSetup(class USQUserWidget* Widget, class UBaseRadialMenu_C* RadialMenu, class UBP_RadialItemModel_C* ActionModel)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPCenterPopulatorVehicleTowing_C", "FinishWidgetSetup");

	Params::BPCenterPopulatorVehicleTowing_C_FinishWidgetSetup Parms{};

	Parms.Widget = Widget;
	Parms.RadialMenu = RadialMenu;
	Parms.ActionModel = ActionModel;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BPCenterPopulatorVehicleTowing.BPCenterPopulatorVehicleTowing_C.InitialSetup
// (Protected, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQUserWidget*                    Widget                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBP_RadialItemModel_C*            Model                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UBaseRadialMenu_C*                RadialMenu                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBPCenterPopulatorVehicleTowing_C::InitialSetup(class USQUserWidget* Widget, class UBP_RadialItemModel_C* Model, class UBaseRadialMenu_C* RadialMenu)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPCenterPopulatorVehicleTowing_C", "InitialSetup");

	Params::BPCenterPopulatorVehicleTowing_C_InitialSetup Parms{};

	Parms.Widget = Widget;
	Parms.Model = Model;
	Parms.RadialMenu = RadialMenu;

	UObject::ProcessEvent(Func, &Parms);
}

}
