#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQFaction

#include "Basic.hpp"

#include "BP_SQFaction_classes.hpp"
#include "BP_SQFaction_parameters.hpp"


namespace SDK
{

// Function BP_SQFaction.BP_SQFaction_C.TryGetRoleGroupingStrategies
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// TArray<struct FSQRoleGroupingStrategy>  GroupingStrategies                                     (Parm, OutParm)

void UBP_SQFaction_C::TryGetRoleGroupingStrategies(bool* Success, TArray<struct FSQRoleGroupingStrategy>* GroupingStrategies)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetRoleGroupingStrategies");

	Params::BP_SQFaction_C_TryGetRoleGroupingStrategies Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (GroupingStrategies != nullptr)
		*GroupingStrategies = std::move(Parms.GroupingStrategies);
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetDeployableGroupingStrategies
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// TArray<struct FSQDeployableGroupingStrategy>GroupingStrategies                                     (Parm, OutParm)

void UBP_SQFaction_C::TryGetDeployableGroupingStrategies(bool* Success, TArray<struct FSQDeployableGroupingStrategy>* GroupingStrategies)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetDeployableGroupingStrategies");

	Params::BP_SQFaction_C_TryGetDeployableGroupingStrategies Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (GroupingStrategies != nullptr)
		*GroupingStrategies = std::move(Parms.GroupingStrategies);
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetActionGroupingStrategies
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// TArray<struct FSQActionGroupingStrategy>GroupingStrategies                                     (Parm, OutParm)

void UBP_SQFaction_C::TryGetActionGroupingStrategies(bool* Success, TArray<struct FSQActionGroupingStrategy>* GroupingStrategies)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetActionGroupingStrategies");

	Params::BP_SQFaction_C_TryGetActionGroupingStrategies Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (GroupingStrategies != nullptr)
		*GroupingStrategies = std::move(Parms.GroupingStrategies);
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetFlagForAnimatedFlags
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// TSoftObjectPtr<class UTexture2D>        OutTexture                                             (Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQFaction_C::TryGetFlagForAnimatedFlags(TSoftObjectPtr<class UTexture2D>* OutTexture)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetFlagForAnimatedFlags");

	Params::BP_SQFaction_C_TryGetFlagForAnimatedFlags Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutTexture != nullptr)
		*OutTexture = Parms.OutTexture;

	return Parms.ReturnValue;
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetFactionEntry
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// struct FSQFactionEntry                  FactionEntry                                           (Parm, OutParm, HasGetValueTypeHash)

void UBP_SQFaction_C::TryGetFactionEntry(bool* Success, struct FSQFactionEntry* FactionEntry) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetFactionEntry");

	Params::BP_SQFaction_C_TryGetFactionEntry Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (FactionEntry != nullptr)
		*FactionEntry = std::move(Parms.FactionEntry);
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetFlagForFullScreen
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// TSoftObjectPtr<class UTexture2D>        OutTexture                                             (Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQFaction_C::TryGetFlagForFullScreen(TSoftObjectPtr<class UTexture2D>* OutTexture) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetFlagForFullScreen");

	Params::BP_SQFaction_C_TryGetFlagForFullScreen Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutTexture != nullptr)
		*OutTexture = Parms.OutTexture;

	return Parms.ReturnValue;
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetFlagForMap
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// TSoftObjectPtr<class UTexture2D>        OutTexture                                             (Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQFaction_C::TryGetFlagForMap(TSoftObjectPtr<class UTexture2D>* OutTexture) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetFlagForMap");

	Params::BP_SQFaction_C_TryGetFlagForMap Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutTexture != nullptr)
		*OutTexture = Parms.OutTexture;

	return Parms.ReturnValue;
}


// Function BP_SQFaction.BP_SQFaction_C.TryGetRallyPointMesh
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USQLayer*                         Layer                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// TSoftObjectPtr<class UStaticMesh>       OutMesh                                                (Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQFaction_C::TryGetRallyPointMesh(class USQLayer* Layer, TSoftObjectPtr<class UStaticMesh>* OutMesh) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQFaction_C", "TryGetRallyPointMesh");

	Params::BP_SQFaction_C_TryGetRallyPointMesh Parms{};

	Parms.Layer = Layer;

	UObject::ProcessEvent(Func, &Parms);

	if (OutMesh != nullptr)
		*OutMesh = Parms.OutMesh;

	return Parms.ReturnValue;
}

}

