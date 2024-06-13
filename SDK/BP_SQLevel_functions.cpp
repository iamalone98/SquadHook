#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQLevel

#include "Basic.hpp"

#include "BP_SQLevel_classes.hpp"
#include "BP_SQLevel_parameters.hpp"


namespace SDK
{

// Function BP_SQLevel.BP_SQLevel_C.TryGetLevelEntry
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// struct FSQLevelEntry                    LevelEntry                                             (Parm, OutParm, HasGetValueTypeHash)

void UBP_SQLevel_C::TryGetLevelEntry(bool* Success, struct FSQLevelEntry* LevelEntry) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "TryGetLevelEntry");

	Params::BP_SQLevel_C_TryGetLevelEntry Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (LevelEntry != nullptr)
		*LevelEntry = std::move(Parms.LevelEntry);
}


// Function BP_SQLevel.BP_SQLevel_C.TryGetLoadingScreen
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// TSoftObjectPtr<class UTexture2D>        OutLoadingScreen                                       (Parm, OutParm, UObjectWrapper, HasGetValueTypeHash)
// struct FVector2D                        InViewportSize                                         (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQLevel_C::TryGetLoadingScreen(TSoftObjectPtr<class UTexture2D>* OutLoadingScreen, const struct FVector2D& InViewportSize) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "TryGetLoadingScreen");

	Params::BP_SQLevel_C_TryGetLoadingScreen Parms{};

	Parms.InViewportSize = std::move(InViewportSize);

	UObject::ProcessEvent(Func, &Parms);

	if (OutLoadingScreen != nullptr)
		*OutLoadingScreen = Parms.OutLoadingScreen;

	return Parms.ReturnValue;
}


// Function BP_SQLevel.BP_SQLevel_C.TryGetDescription
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class FText                             OutDescription                                         (Parm, OutParm)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQLevel_C::TryGetDescription(class FText* OutDescription) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "TryGetDescription");

	Params::BP_SQLevel_C_TryGetDescription Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutDescription != nullptr)
		*OutDescription = std::move(Parms.OutDescription);

	return Parms.ReturnValue;
}


// Function BP_SQLevel.BP_SQLevel_C.TryGetDisplayName
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class FText                             OutDisplayName                                         (Parm, OutParm)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQLevel_C::TryGetDisplayName(class FText* OutDisplayName) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "TryGetDisplayName");

	Params::BP_SQLevel_C_TryGetDisplayName Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutDisplayName != nullptr)
		*OutDisplayName = std::move(Parms.OutDisplayName);

	return Parms.ReturnValue;
}


// Function BP_SQLevel.BP_SQLevel_C.TryGetLoadingMusic
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// class USoundBase*                       OutLoadingMusic                                        (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQLevel_C::TryGetLoadingMusic(class USoundBase** OutLoadingMusic) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "TryGetLoadingMusic");

	Params::BP_SQLevel_C_TryGetLoadingMusic Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutLoadingMusic != nullptr)
		*OutLoadingMusic = Parms.OutLoadingMusic;

	return Parms.ReturnValue;
}


// Function BP_SQLevel.BP_SQLevel_C.CanFactionOperate
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class USQFactionSetup*                  FactionSetup                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQLayer*                         Layer                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SQLevel_C::CanFactionOperate(class USQFactionSetup* FactionSetup, class USQLayer* Layer) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "CanFactionOperate");

	Params::BP_SQLevel_C_CanFactionOperate Parms{};

	Parms.FactionSetup = FactionSetup;
	Parms.Layer = Layer;

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_SQLevel.BP_SQLevel_C.GetBiomeId
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// class FName                             ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class FName UBP_SQLevel_C::GetBiomeId() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SQLevel_C", "GetBiomeId");

	Params::BP_SQLevel_C_GetBiomeId Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
