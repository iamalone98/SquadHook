#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQRestriction_DeployableCount

#include "Basic.hpp"

#include "BP_SQRestriction_DeployableCount_classes.hpp"
#include "BP_SQRestriction_DeployableCount_parameters.hpp"


namespace SDK
{

// Function BP_SQRestriction_DeployableCount.BP_SQRestriction_DeployableCount_C.OnPlayerAddUsage
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerController*              InPlayer                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   OutAddedUsage                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_SQRestriction_DeployableCount_C::OnPlayerAddUsage(class ASQPlayerController* InPlayer, int32* OutAddedUsage) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQRestriction_DeployableCount_C", "OnPlayerAddUsage");

	Params::BP_SQRestriction_DeployableCount_C_OnPlayerAddUsage Parms{};

	Parms.InPlayer = InPlayer;

	UObject::ProcessEvent(Func, &Parms);

	if (OutAddedUsage != nullptr)
		*OutAddedUsage = Parms.OutAddedUsage;
}


// Function BP_SQRestriction_DeployableCount.BP_SQRestriction_DeployableCount_C.OnTeamAddUsage
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQTeam*                          InTeam                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   OutAddedUsage                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_SQRestriction_DeployableCount_C::OnTeamAddUsage(class ASQTeam* InTeam, int32* OutAddedUsage) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQRestriction_DeployableCount_C", "OnTeamAddUsage");

	Params::BP_SQRestriction_DeployableCount_C_OnTeamAddUsage Parms{};

	Parms.InTeam = InTeam;

	UObject::ProcessEvent(Func, &Parms);

	if (OutAddedUsage != nullptr)
		*OutAddedUsage = Parms.OutAddedUsage;
}


// Function BP_SQRestriction_DeployableCount.BP_SQRestriction_DeployableCount_C.GetLocalFobDeployableCount
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerController*              In_Player                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Out_Used                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_SQRestriction_DeployableCount_C::GetLocalFobDeployableCount(class ASQPlayerController* In_Player, int32* Out_Used) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQRestriction_DeployableCount_C", "GetLocalFobDeployableCount");

	Params::BP_SQRestriction_DeployableCount_C_GetLocalFobDeployableCount Parms{};

	Parms.In_Player = In_Player;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Used != nullptr)
		*Out_Used = Parms.Out_Used;
}

}

