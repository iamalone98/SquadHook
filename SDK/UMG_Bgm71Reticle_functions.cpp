#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Bgm71Reticle

#include "Basic.hpp"

#include "UMG_Bgm71Reticle_classes.hpp"
#include "UMG_Bgm71Reticle_parameters.hpp"


namespace SDK
{

// Function UMG_Bgm71Reticle.UMG_Bgm71Reticle_C.ExecuteUbergraph_UMG_Bgm71Reticle
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_Bgm71Reticle_C::ExecuteUbergraph_UMG_Bgm71Reticle(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Bgm71Reticle_C", "ExecuteUbergraph_UMG_Bgm71Reticle");

	Params::UMG_Bgm71Reticle_C_ExecuteUbergraph_UMG_Bgm71Reticle Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_Bgm71Reticle.UMG_Bgm71Reticle_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_Bgm71Reticle_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_Bgm71Reticle_C", "Tick");

	Params::UMG_Bgm71Reticle_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}

}

