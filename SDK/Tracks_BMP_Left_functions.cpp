#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tracks_BMP_Left

#include "Basic.hpp"

#include "Tracks_BMP_Left_classes.hpp"
#include "Tracks_BMP_Left_parameters.hpp"


namespace SDK
{

// Function Tracks_BMP_Left.Tracks_BMP_Left_C.ExecuteUbergraph_Tracks_BMP_Left
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ATracks_BMP_Left_C::ExecuteUbergraph_Tracks_BMP_Left(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tracks_BMP_Left_C", "ExecuteUbergraph_Tracks_BMP_Left");

	Params::Tracks_BMP_Left_C_ExecuteUbergraph_Tracks_BMP_Left Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Tracks_BMP_Left.Tracks_BMP_Left_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ATracks_BMP_Left_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Tracks_BMP_Left_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}

}
