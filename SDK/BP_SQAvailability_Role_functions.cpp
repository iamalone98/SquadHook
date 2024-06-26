#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQAvailability_Role

#include "Basic.hpp"

#include "BP_SQAvailability_Role_classes.hpp"
#include "BP_SQAvailability_Role_parameters.hpp"


namespace SDK
{

// Function BP_SQAvailability_Role.BP_SQAvailability_Role_C.GetRearmRefundPercentage
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// int32                                   ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

int32 UBP_SQAvailability_Role_C::GetRearmRefundPercentage() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQAvailability_Role_C", "GetRearmRefundPercentage");

	Params::BP_SQAvailability_Role_C_GetRearmRefundPercentage Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_SQAvailability_Role.BP_SQAvailability_Role_C.GetInsufficientAmmoReamFailureReason
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// struct FDataTableRowHandle              ReturnValue                                            (Parm, OutParm, ReturnParm, NoDestructor)

struct FDataTableRowHandle UBP_SQAvailability_Role_C::GetInsufficientAmmoReamFailureReason() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQAvailability_Role_C", "GetInsufficientAmmoReamFailureReason");

	Params::BP_SQAvailability_Role_C_GetInsufficientAmmoReamFailureReason Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_SQAvailability_Role.BP_SQAvailability_Role_C.GetAvailabilityForPlayer
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerController*              InPlayer                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FSQAvailabilityState             InTeamStatus                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FSQAvailabilityState             OutPlayerStatus                                        (Parm, OutParm)

void UBP_SQAvailability_Role_C::GetAvailabilityForPlayer(class ASQPlayerController* InPlayer, const struct FSQAvailabilityState& InTeamStatus, struct FSQAvailabilityState* OutPlayerStatus) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQAvailability_Role_C", "GetAvailabilityForPlayer");

	Params::BP_SQAvailability_Role_C_GetAvailabilityForPlayer Parms{};

	Parms.InPlayer = InPlayer;
	Parms.InTeamStatus = std::move(InTeamStatus);

	UObject::ProcessEvent(Func, &Parms);

	if (OutPlayerStatus != nullptr)
		*OutPlayerStatus = std::move(Parms.OutPlayerStatus);
}


// Function BP_SQAvailability_Role.BP_SQAvailability_Role_C.UpdateTeamAvailability
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQTeam*                          InTeam                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FSQAvailabilityState             OutTeamStatus                                          (Parm, OutParm)

void UBP_SQAvailability_Role_C::UpdateTeamAvailability(class ASQTeam* InTeam, struct FSQAvailabilityState* OutTeamStatus) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQAvailability_Role_C", "UpdateTeamAvailability");

	Params::BP_SQAvailability_Role_C_UpdateTeamAvailability Parms{};

	Parms.InTeam = InTeam;

	UObject::ProcessEvent(Func, &Parms);

	if (OutTeamStatus != nullptr)
		*OutTeamStatus = std::move(Parms.OutTeamStatus);
}

}

