#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQMapGridLines

#include "Basic.hpp"

#include "W_SQMapGridLines_classes.hpp"
#include "W_SQMapGridLines_parameters.hpp"


namespace SDK
{

// Function W_SQMapGridLines.W_SQMapGridLines_C.ExecuteUbergraph_W_SQMapGridLines
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLines_C::ExecuteUbergraph_W_SQMapGridLines(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLines_C", "ExecuteUbergraph_W_SQMapGridLines");

	Params::W_SQMapGridLines_C_ExecuteUbergraph_W_SQMapGridLines Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapGridLines.W_SQMapGridLines_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_SQMapGridLines_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLines_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SQMapGridLines.W_SQMapGridLines_C.Update Grid Opacity
// (BlueprintCallable, BlueprintEvent)

void UW_SQMapGridLines_C::Update_Grid_Opacity()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLines_C", "Update Grid Opacity");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SQMapGridLines.W_SQMapGridLines_C.UpdateZoom
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   ZoomAmount                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLines_C::UpdateZoom(float ZoomAmount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLines_C", "UpdateZoom");

	Params::W_SQMapGridLines_C_UpdateZoom Parms{};

	Parms.ZoomAmount = ZoomAmount;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapGridLines.W_SQMapGridLines_C.InitializeTexture
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector2D                        GridNumbers                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   StartingZoom                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLines_C::InitializeTexture(const struct FVector2D& GridNumbers, float StartingZoom)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLines_C", "InitializeTexture");

	Params::W_SQMapGridLines_C_InitializeTexture Parms{};

	Parms.GridNumbers = std::move(GridNumbers);
	Parms.StartingZoom = StartingZoom;

	UObject::ProcessEvent(Func, &Parms);
}

}
