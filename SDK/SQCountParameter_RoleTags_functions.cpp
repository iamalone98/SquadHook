#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQCountParameter_RoleTags

#include "Basic.hpp"

#include "SQCountParameter_RoleTags_classes.hpp"
#include "SQCountParameter_RoleTags_parameters.hpp"


namespace SDK
{

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetCountedTaggedRole
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerState*                   In_PlayerState                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Out_Counted                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USQCountParameter_RoleTags_C::GetCountedTaggedRole(class ASQPlayerState* In_PlayerState, int32* Out_Counted) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SQCountParameter_RoleTags_C", "GetCountedTaggedRole");

	Params::SQCountParameter_RoleTags_C_GetCountedTaggedRole Parms{};

	Parms.In_PlayerState = In_PlayerState;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Counted != nullptr)
		*Out_Counted = Parms.Out_Counted;
}


// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.TryGetValueForTeam
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQTeam*                          InTeam                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   OutValue                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool USQCountParameter_RoleTags_C::TryGetValueForTeam(const class ASQTeam* InTeam, int32* OutValue) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SQCountParameter_RoleTags_C", "TryGetValueForTeam");

	Params::SQCountParameter_RoleTags_C_TryGetValueForTeam Parms{};

	Parms.InTeam = InTeam;

	UObject::ProcessEvent(Func, &Parms);

	if (OutValue != nullptr)
		*OutValue = Parms.OutValue;

	return Parms.ReturnValue;
}


// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.TryGetValueForPlayer
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerController*              InPlayer                                               (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   OutValue                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool USQCountParameter_RoleTags_C::TryGetValueForPlayer(const class ASQPlayerController* InPlayer, int32* OutValue) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SQCountParameter_RoleTags_C", "TryGetValueForPlayer");

	Params::SQCountParameter_RoleTags_C_TryGetValueForPlayer Parms{};

	Parms.InPlayer = InPlayer;

	UObject::ProcessEvent(Func, &Parms);

	if (OutValue != nullptr)
		*OutValue = Parms.OutValue;

	return Parms.ReturnValue;
}


// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetMaxCountForTeamsize
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQTeam*                          In_Team                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Out_Count                                              (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USQCountParameter_RoleTags_C::GetMaxCountForTeamsize(class ASQTeam* In_Team, int32* Out_Count) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SQCountParameter_RoleTags_C", "GetMaxCountForTeamsize");

	Params::SQCountParameter_RoleTags_C_GetMaxCountForTeamsize Parms{};

	Parms.In_Team = In_Team;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Count != nullptr)
		*Out_Count = Parms.Out_Count;
}


// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetMaxCountForSquadSize
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class ASQPlayerController*              In_Player                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   Out_Count                                              (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void USQCountParameter_RoleTags_C::GetMaxCountForSquadSize(class ASQPlayerController* In_Player, int32* Out_Count) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("SQCountParameter_RoleTags_C", "GetMaxCountForSquadSize");

	Params::SQCountParameter_RoleTags_C_GetMaxCountForSquadSize Parms{};

	Parms.In_Player = In_Player;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Count != nullptr)
		*Out_Count = Parms.Out_Count;
}

}

