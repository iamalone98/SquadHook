#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: bmp1_turret_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "bmp1_turret_Skeleton_AnimBlueprint_classes.hpp"
#include "bmp1_turret_Skeleton_AnimBlueprint_parameters.hpp"


namespace SDK
{

// Function bmp1_turret_Skeleton_AnimBlueprint.bmp1_turret_Skeleton_AnimBlueprint_C.ExecuteUbergraph_bmp1_turret_Skeleton_AnimBlueprint
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void Ubmp1_turret_Skeleton_AnimBlueprint_C::ExecuteUbergraph_bmp1_turret_Skeleton_AnimBlueprint(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("bmp1_turret_Skeleton_AnimBlueprint_C", "ExecuteUbergraph_bmp1_turret_Skeleton_AnimBlueprint");

	Params::bmp1_turret_Skeleton_AnimBlueprint_C_ExecuteUbergraph_bmp1_turret_Skeleton_AnimBlueprint Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function bmp1_turret_Skeleton_AnimBlueprint.bmp1_turret_Skeleton_AnimBlueprint_C.AnimGraph
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPoseLink                        Param_AnimGraph                                        (Parm, OutParm, NoDestructor)

void Ubmp1_turret_Skeleton_AnimBlueprint_C::AnimGraph(struct FPoseLink* Param_AnimGraph)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("bmp1_turret_Skeleton_AnimBlueprint_C", "AnimGraph");

	Params::bmp1_turret_Skeleton_AnimBlueprint_C_AnimGraph Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_AnimGraph != nullptr)
		*Param_AnimGraph = std::move(Parms.Param_AnimGraph);
}

}

