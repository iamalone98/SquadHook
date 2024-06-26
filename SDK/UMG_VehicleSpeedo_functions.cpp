#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VehicleSpeedo

#include "Basic.hpp"

#include "UMG_VehicleSpeedo_classes.hpp"
#include "UMG_VehicleSpeedo_parameters.hpp"


namespace SDK
{

// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.ExecuteUbergraph_UMG_VehicleSpeedo
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VehicleSpeedo_C::ExecuteUbergraph_UMG_VehicleSpeedo(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "ExecuteUbergraph_UMG_VehicleSpeedo");

	Params::UMG_VehicleSpeedo_C_ExecuteUbergraph_UMG_VehicleSpeedo Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Validate Visibility
// (BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Validate_Visibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Validate Visibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Soldier Died
// (BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Soldier_Died()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Soldier Died");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Get Soldier
// (BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Get_Soldier()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Get Soldier");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Changed Team
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQTeamState*                     OldTeam                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQTeamState*                     NewTeam                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VehicleSpeedo_C::Changed_Team(class ASQTeamState* OldTeam, class ASQTeamState* NewTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Changed Team");

	Params::UMG_VehicleSpeedo_C_Changed_Team Parms{};

	Parms.OldTeam = OldTeam;
	Parms.NewTeam = NewTeam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Update Vehicle
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQVehicle*                       Vehicle                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQVehicleSeatComponent*          FromSeat                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class USQVehicleSeatComponent*          ToSeat                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VehicleSpeedo_C::Update_Vehicle(class ASQSoldier* Soldier, class ASQVehicle* Vehicle, class USQVehicleSeatComponent* FromSeat, class USQVehicleSeatComponent* ToSeat)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Update Vehicle");

	Params::UMG_VehicleSpeedo_C_Update_Vehicle Parms{};

	Parms.Soldier = Soldier;
	Parms.Vehicle = Vehicle;
	Parms.FromSeat = FromSeat;
	Parms.ToSeat = ToSeat;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Dial
// (BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Dial()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Dial");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UUMG_VehicleSpeedo_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Tick");

	Params::UMG_VehicleSpeedo_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.GearText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UUMG_VehicleSpeedo_C::GearText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "GearText");

	Params::UMG_VehicleSpeedo_C_GearText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Widget
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Widget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Widget");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.GearColor
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FLinearColor                     ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

struct FLinearColor UUMG_VehicleSpeedo_C::GearColor()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "GearColor");

	Params::UMG_VehicleSpeedo_C_GearColor Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.DrawDialNumbers
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::DrawDialNumbers()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "DrawDialNumbers");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Clear Dial Numbers
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Clear_Dial_Numbers()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Clear Dial Numbers");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Update Revs
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Update_Revs()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Update Revs");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Icon
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Hide Widget
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Hide_Widget()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Hide Widget");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Rearm Cost
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Rearm_Cost()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Rearm Cost");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Data
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Data()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Data");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Handbrake
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Handbrake()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Handbrake");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Update Handbrake
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Update_Handbrake()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Update Handbrake");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.GetSpeedometerRange
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// float                                   ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

float UUMG_VehicleSpeedo_C::GetSpeedometerRange()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "GetSpeedometerRange");

	Params::UMG_VehicleSpeedo_C_GetSpeedometerRange Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Refresh Amphibious Icon
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Refresh_Amphibious_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Refresh Amphibious Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function UMG_VehicleSpeedo.UMG_VehicleSpeedo_C.Update Amphibious Icon
// (Public, BlueprintCallable, BlueprintEvent)

void UUMG_VehicleSpeedo_C::Update_Amphibious_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("UMG_VehicleSpeedo_C", "Update Amphibious Icon");

	UObject::ProcessEvent(Func, nullptr);
}

}

