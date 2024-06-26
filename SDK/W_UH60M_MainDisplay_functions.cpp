#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_UH60M_MainDisplay

#include "Basic.hpp"

#include "W_UH60M_MainDisplay_classes.hpp"
#include "W_UH60M_MainDisplay_parameters.hpp"


namespace SDK
{

// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.ExecuteUbergraph_W_UH60M_MainDisplay
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_UH60M_MainDisplay_C::ExecuteUbergraph_W_UH60M_MainDisplay(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "ExecuteUbergraph_W_UH60M_MainDisplay");

	Params::W_UH60M_MainDisplay_C_ExecuteUbergraph_W_UH60M_MainDisplay Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Manage Update
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Can_Update                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_UH60M_MainDisplay_C::Manage_Update(bool Can_Update)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Manage Update");

	Params::W_UH60M_MainDisplay_C_Manage_Update Parms{};

	Parms.Can_Update = Can_Update;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Screen Off
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Screen_Off()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Screen Off");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Screen On
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Screen_On()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Screen On");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Update RPM
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Update_RPM()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Update RPM");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Update MainDisplay
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Update_MainDisplay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Update MainDisplay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Update TAXI
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Update_TAXI()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Update TAXI");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Refresh HelicopterDisplay
// (BlueprintCallable, BlueprintEvent)

void UW_UH60M_MainDisplay_C::Refresh_HelicopterDisplay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Refresh HelicopterDisplay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_UH60M_MainDisplay.W_UH60M_MainDisplay_C.Set Owning Vehicle
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ABP_Generic_Helicopter_C*         Param_OwningVehicle                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_UH60M_MainDisplay_C::Set_Owning_Vehicle(class ABP_Generic_Helicopter_C* Param_OwningVehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_UH60M_MainDisplay_C", "Set Owning Vehicle");

	Params::W_UH60M_MainDisplay_C_Set_Owning_Vehicle Parms{};

	Parms.Param_OwningVehicle = Param_OwningVehicle;

	UObject::ProcessEvent(Func, &Parms);
}

}

