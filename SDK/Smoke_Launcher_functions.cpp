#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Smoke_Launcher

#include "Basic.hpp"

#include "Smoke_Launcher_classes.hpp"
#include "Smoke_Launcher_parameters.hpp"


namespace SDK
{

// Function Smoke_Launcher.Smoke_Launcher_C.ExecuteUbergraph_Smoke_Launcher
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ASmoke_Launcher_C::ExecuteUbergraph_Smoke_Launcher(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Smoke_Launcher_C", "ExecuteUbergraph_Smoke_Launcher");

	Params::Smoke_Launcher_C_ExecuteUbergraph_Smoke_Launcher Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function Smoke_Launcher.Smoke_Launcher_C.BlueprintOnFire
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          Origin                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ASmoke_Launcher_C::BlueprintOnFire(const struct FVector& Origin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("Smoke_Launcher_C", "BlueprintOnFire");

	Params::Smoke_Launcher_C_BlueprintOnFire Parms{};

	Parms.Origin = std::move(Origin);

	UObject::ProcessEvent(Func, &Parms);
}

}
