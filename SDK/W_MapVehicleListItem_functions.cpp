#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MapVehicleListItem

#include "Basic.hpp"

#include "W_MapVehicleListItem_classes.hpp"
#include "W_MapVehicleListItem_parameters.hpp"


namespace SDK
{

// Function W_MapVehicleListItem.W_MapVehicleListItem_C.ExecuteUbergraph_W_MapVehicleListItem
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_MapVehicleListItem_C::ExecuteUbergraph_W_MapVehicleListItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "ExecuteUbergraph_W_MapVehicleListItem");

	Params::W_MapVehicleListItem_C_ExecuteUbergraph_W_MapVehicleListItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_MapVehicleListItem_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateStatus
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FSQAvailabilityState_Vehicle     State                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ContainsInstancedReference)

void UW_MapVehicleListItem_C::UpdateStatus(const struct FSQAvailabilityState_Vehicle& State)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateStatus");

	Params::W_MapVehicleListItem_C_UpdateStatus Parms{};

	Parms.State = std::move(State);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateTimer
// (BlueprintCallable, BlueprintEvent)

void UW_MapVehicleListItem_C::UpdateTimer()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateTimer");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.GetDefaultSpawnDelay
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FTimespan                        Delay                                                  (Parm, OutParm, ZeroConstructor, NoDestructor, HasGetValueTypeHash)

void UW_MapVehicleListItem_C::GetDefaultSpawnDelay(struct FTimespan* Delay)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "GetDefaultSpawnDelay");

	Params::W_MapVehicleListItem_C_GetDefaultSpawnDelay Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Delay != nullptr)
		*Delay = std::move(Parms.Delay);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateUsed
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   Used                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_MapVehicleListItem_C::UpdateUsed(int32 Used)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateUsed");

	Params::W_MapVehicleListItem_C_UpdateUsed Parms{};

	Parms.Used = Used;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateAvailable
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   Available                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQAvailability*                  Target                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_MapVehicleListItem_C::UpdateAvailable(int32 Available, class USQAvailability* Target)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateAvailable");

	Params::W_MapVehicleListItem_C_UpdateAvailable Parms{};

	Parms.Available = Available;
	Parms.Target = Target;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateDelay
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FDateTime                        NextAvailability                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, NoDestructor, HasGetValueTypeHash)

void UW_MapVehicleListItem_C::UpdateDelay(const struct FDateTime& NextAvailability)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateDelay");

	Params::W_MapVehicleListItem_C_UpdateDelay Parms{};

	Parms.NextAvailability = std::move(NextAvailability);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateUnavailabilityReason
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FDataTableRowHandle              Reason                                                 (BlueprintVisible, BlueprintReadOnly, Parm, NoDestructor)

void UW_MapVehicleListItem_C::UpdateUnavailabilityReason(const struct FDataTableRowHandle& Reason)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateUnavailabilityReason");

	Params::W_MapVehicleListItem_C_UpdateUnavailabilityReason Parms{};

	Parms.Reason = std::move(Reason);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.ShouldShowDetails
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// ESQIntelligence                         Intel                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ShowDetails                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_MapVehicleListItem_C::ShouldShowDetails(ESQIntelligence Intel, bool* ShowDetails)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "ShouldShowDetails");

	Params::W_MapVehicleListItem_C_ShouldShowDetails Parms{};

	Parms.Intel = Intel;

	UObject::ProcessEvent(Func, &Parms);

	if (ShowDetails != nullptr)
		*ShowDetails = Parms.ShowDetails;
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.GetNextAvailabilityTimer
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             OutText                                                (Parm, OutParm)

void UW_MapVehicleListItem_C::GetNextAvailabilityTimer(class FText* OutText)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "GetNextAvailabilityTimer");

	Params::W_MapVehicleListItem_C_GetNextAvailabilityTimer Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (OutText != nullptr)
		*OutText = std::move(Parms.OutText);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.HasTimer
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Param_HasTimer                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_MapVehicleListItem_C::HasTimer(bool* Param_HasTimer)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "HasTimer");

	Params::W_MapVehicleListItem_C_HasTimer Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_HasTimer != nullptr)
		*Param_HasTimer = Parms.Param_HasTimer;
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateCollapsing
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   In_ModifierPct                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Out_Collapsed                                          (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_MapVehicleListItem_C::UpdateCollapsing(int32 In_ModifierPct, bool* Out_Collapsed)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateCollapsing");

	Params::W_MapVehicleListItem_C_UpdateCollapsing Parms{};

	Parms.In_ModifierPct = In_ModifierPct;

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Collapsed != nullptr)
		*Out_Collapsed = Parms.Out_Collapsed;
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.ToHumanReadableTime
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FTimespan                        InTimespan                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, NoDestructor, HasGetValueTypeHash)
// class FText                             Result                                                 (Parm, OutParm)

void UW_MapVehicleListItem_C::ToHumanReadableTime(const struct FTimespan& InTimespan, class FText* Result)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "ToHumanReadableTime");

	Params::W_MapVehicleListItem_C_ToHumanReadableTime Parms{};

	Parms.InTimespan = std::move(InTimespan);

	UObject::ProcessEvent(Func, &Parms);

	if (Result != nullptr)
		*Result = std::move(Parms.Result);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.Init Delay
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Out_Should_Update_Timer                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_MapVehicleListItem_C::Init_Delay(bool* Out_Should_Update_Timer)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "Init Delay");

	Params::W_MapVehicleListItem_C_Init_Delay Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Out_Should_Update_Timer != nullptr)
		*Out_Should_Update_Timer = Parms.Out_Should_Update_Timer;
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.Finalize Layout
// (Public, BlueprintCallable, BlueprintEvent)

void UW_MapVehicleListItem_C::Finalize_Layout()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "Finalize Layout");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_MapVehicleListItem.W_MapVehicleListItem_C.UpdateDepletedSingleUse
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQAvailability*                  In_Availability                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FSQAvailabilityState             In_State                                               (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)

void UW_MapVehicleListItem_C::UpdateDepletedSingleUse(class USQAvailability* In_Availability, const struct FSQAvailabilityState& In_State)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_MapVehicleListItem_C", "UpdateDepletedSingleUse");

	Params::W_MapVehicleListItem_C_UpdateDepletedSingleUse Parms{};

	Parms.In_Availability = In_Availability;
	Parms.In_State = std::move(In_State);

	UObject::ProcessEvent(Func, &Parms);
}

}

