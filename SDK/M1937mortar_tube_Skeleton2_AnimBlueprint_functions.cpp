#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: M1937mortar_tube_Skeleton2_AnimBlueprint

#include "Basic.hpp"

#include "M1937mortar_tube_Skeleton2_AnimBlueprint_classes.hpp"
#include "M1937mortar_tube_Skeleton2_AnimBlueprint_parameters.hpp"


namespace SDK
{

// Function m1937mortar_tube_Skeleton2_AnimBlueprint.m1937mortar_tube_Skeleton2_AnimBlueprint_C.ExecuteUbergraph_m1937mortar_tube_Skeleton2_AnimBlueprint
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UM1937mortar_tube_Skeleton2_AnimBlueprint_C::ExecuteUbergraph_m1937mortar_tube_Skeleton2_AnimBlueprint(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("m1937mortar_tube_Skeleton2_AnimBlueprint_C", "ExecuteUbergraph_m1937mortar_tube_Skeleton2_AnimBlueprint");

	Params::M1937mortar_tube_Skeleton2_AnimBlueprint_C_ExecuteUbergraph_m1937mortar_tube_Skeleton2_AnimBlueprint Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function m1937mortar_tube_Skeleton2_AnimBlueprint.m1937mortar_tube_Skeleton2_AnimBlueprint_C.AnimGraph
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPoseLink                        Param_AnimGraph                                        (Parm, OutParm, NoDestructor)

void UM1937mortar_tube_Skeleton2_AnimBlueprint_C::AnimGraph(struct FPoseLink* Param_AnimGraph)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("m1937mortar_tube_Skeleton2_AnimBlueprint_C", "AnimGraph");

	Params::M1937mortar_tube_Skeleton2_AnimBlueprint_C_AnimGraph Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_AnimGraph != nullptr)
		*Param_AnimGraph = std::move(Parms.Param_AnimGraph);
}

}
