#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmplacedSPG9_Tripod

#include "Basic.hpp"

#include "BP_EmplacedSPG9_Tripod_classes.hpp"
#include "BP_EmplacedSPG9_Tripod_parameters.hpp"


namespace SDK
{

// Function BP_EmplacedSPG9_Tripod.BP_EmplacedSPG9_Tripod_C.GetSoldierAttachComponent
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USceneComponent*                  ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USceneComponent* ABP_EmplacedSPG9_Tripod_C::GetSoldierAttachComponent() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_EmplacedSPG9_Tripod_C", "GetSoldierAttachComponent");

	Params::BP_EmplacedSPG9_Tripod_C_GetSoldierAttachComponent Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

