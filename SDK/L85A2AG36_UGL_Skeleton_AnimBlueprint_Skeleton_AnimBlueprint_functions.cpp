#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint

#include "Basic.hpp"

#include "L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_classes.hpp"
#include "L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_parameters.hpp"


namespace SDK
{

// Function L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint.L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C.ExecuteUbergraph_L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UL85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C::ExecuteUbergraph_L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C", "ExecuteUbergraph_L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint");

	Params::L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C_ExecuteUbergraph_L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint.L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C.AnimGraph
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPoseLink                        Param_AnimGraph                                        (Parm, OutParm, NoDestructor)

void UL85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C::AnimGraph(struct FPoseLink* Param_AnimGraph)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C", "AnimGraph");

	Params::L85A2AG36_UGL_Skeleton_AnimBlueprint_Skeleton_AnimBlueprint_C_AnimGraph Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_AnimGraph != nullptr)
		*Param_AnimGraph = std::move(Parms.Param_AnimGraph);
}

}

