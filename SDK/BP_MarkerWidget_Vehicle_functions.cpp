#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_Vehicle

#include "Basic.hpp"

#include "BP_MarkerWidget_Vehicle_classes.hpp"
#include "BP_MarkerWidget_Vehicle_parameters.hpp"


namespace SDK
{

// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.CloseTooltip__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::CloseTooltip__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "CloseTooltip__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.ExecuteUbergraph_BP_MarkerWidget_Vehicle
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::ExecuteUbergraph_BP_MarkerWidget_Vehicle(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "ExecuteUbergraph_BP_MarkerWidget_Vehicle");

	Params::BP_MarkerWidget_Vehicle_C_ExecuteUbergraph_BP_MarkerWidget_Vehicle Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateVisibilityEvent
// (BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateVisibilityEvent()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateVisibilityEvent");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateStateEvent
// (BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateStateEvent()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateStateEvent");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "Tick");

	Params::BP_MarkerWidget_Vehicle_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateVehicleBrush
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateVehicleBrush()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateVehicleBrush");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.GetVehicleIcon
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UTexture*                         NewParam                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::GetVehicleIcon(class UTexture** NewParam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "GetVehicleIcon");

	Params::BP_MarkerWidget_Vehicle_C_GetVehicleIcon Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (NewParam != nullptr)
		*NewParam = Parms.NewParam;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsNeutralTeam
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Param_IsNeutralTeam                                    (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsNeutralTeam(bool* Param_IsNeutralTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsNeutralTeam");

	Params::BP_MarkerWidget_Vehicle_C_IsNeutralTeam Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_IsNeutralTeam != nullptr)
		*Param_IsNeutralTeam = Parms.Param_IsNeutralTeam;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsSameTeam
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    SameTeam                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsSameTeam(bool* SameTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsSameTeam");

	Params::BP_MarkerWidget_Vehicle_C_IsSameTeam Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (SameTeam != nullptr)
		*SameTeam = Parms.SameTeam;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsSameSquad
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    SquadVehicle                                           (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsSameSquad(bool* SquadVehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsSameSquad");

	Params::BP_MarkerWidget_Vehicle_C_IsSameSquad Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (SquadVehicle != nullptr)
		*SquadVehicle = Parms.SquadVehicle;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.GetVehicle
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class ASQVehicle*                       Vehicle                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::GetVehicle(class ASQVehicle** Vehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "GetVehicle");

	Params::BP_MarkerWidget_Vehicle_C_GetVehicle Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Vehicle != nullptr)
		*Vehicle = Parms.Vehicle;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsVehicleEmpty
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Empty                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsVehicleEmpty(bool* Empty)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsVehicleEmpty");

	Params::BP_MarkerWidget_Vehicle_C_IsVehicleEmpty Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Empty != nullptr)
		*Empty = Parms.Empty;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateVehicleConeVisbility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateVehicleConeVisbility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateVehicleConeVisbility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsInVehicle
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    InVehicle                                              (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsInVehicle(bool* InVehicle)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsInVehicle");

	Params::BP_MarkerWidget_Vehicle_C_IsInVehicle Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (InVehicle != nullptr)
		*InVehicle = Parms.InVehicle;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateAngles
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateAngles()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateAngles");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.IsLocalInDriverSeat
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Driver                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MarkerWidget_Vehicle_C::IsLocalInDriverSeat(bool* Driver)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "IsLocalInDriverSeat");

	Params::BP_MarkerWidget_Vehicle_C_IsLocalInDriverSeat Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Driver != nullptr)
		*Driver = Parms.Driver;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.GetLocalSeat
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class USQVehicleSeatComponent*          Seat                                                   (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::GetLocalSeat(class USQVehicleSeatComponent** Seat)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "GetLocalSeat");

	Params::BP_MarkerWidget_Vehicle_C_GetLocalSeat Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Seat != nullptr)
		*Seat = Parms.Seat;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.Get Claimed By
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Is_Claimed                                             (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// int32                                   Claim_ID                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MarkerWidget_Vehicle_C::Get_Claimed_By(bool* Is_Claimed, int32* Claim_ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "Get Claimed By");

	Params::BP_MarkerWidget_Vehicle_C_Get_Claimed_By Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Is_Claimed != nullptr)
		*Is_Claimed = Parms.Is_Claimed;

	if (Claim_ID != nullptr)
		*Claim_ID = Parms.Claim_ID;
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.UpdateSquadInfo
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MarkerWidget_Vehicle_C::UpdateSquadInfo()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "UpdateSquadInfo");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MarkerWidget_Vehicle.BP_MarkerWidget_Vehicle_C.Get 1st Occupant Info
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    Leader                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    Same_Squad                                             (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class FText                             ID                                                     (Parm, OutParm)

void UBP_MarkerWidget_Vehicle_C::Get_1st_Occupant_Info(bool* Success, bool* Leader, bool* Same_Squad, class FText* ID)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MarkerWidget_Vehicle_C", "Get 1st Occupant Info");

	Params::BP_MarkerWidget_Vehicle_C_Get_1st_Occupant_Info Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;

	if (Leader != nullptr)
		*Leader = Parms.Leader;

	if (Same_Squad != nullptr)
		*Same_Squad = Parms.Same_Squad;

	if (ID != nullptr)
		*ID = std::move(Parms.ID);
}

}

