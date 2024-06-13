#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPI_Helicopter

#include "Basic.hpp"

#include "BPI_Helicopter_classes.hpp"
#include "BPI_Helicopter_parameters.hpp"


namespace SDK
{

// Function BPI_Helicopter.BPI_Helicopter_C.Is Using Landing Camera
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Using_Landing_Camera                                   (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void IBPI_Helicopter_C::Is_Using_Landing_Camera(bool* Using_Landing_Camera)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPI_Helicopter_C", "Is Using Landing Camera");

	Params::BPI_Helicopter_C_Is_Using_Landing_Camera Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Using_Landing_Camera != nullptr)
		*Using_Landing_Camera = Parms.Using_Landing_Camera;
}


// Function BPI_Helicopter.BPI_Helicopter_C.Get UI Tint
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FLinearColor                     Color                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void IBPI_Helicopter_C::Get_UI_Tint(struct FLinearColor* Color)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPI_Helicopter_C", "Get UI Tint");

	Params::BPI_Helicopter_C_Get_UI_Tint Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Color != nullptr)
		*Color = std::move(Parms.Color);
}


// Function BPI_Helicopter.BPI_Helicopter_C.Set Landing Camera
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Active                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void IBPI_Helicopter_C::Set_Landing_Camera(bool Active)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BPI_Helicopter_C", "Set Landing Camera");

	Params::BPI_Helicopter_C_Set_Landing_Camera Parms{};

	Parms.Active = Active;

	UObject::ProcessEvent(Func, &Parms);
}

}
