#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MenuCamPawn

#include "Basic.hpp"

#include "MenuCamPawn_classes.hpp"
#include "MenuCamPawn_parameters.hpp"


namespace SDK
{

// Function MenuCamPawn.MenuCamPawn_C.ExecuteUbergraph_MenuCamPawn
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AMenuCamPawn_C::ExecuteUbergraph_MenuCamPawn(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "ExecuteUbergraph_MenuCamPawn");

	Params::MenuCamPawn_C_ExecuteUbergraph_MenuCamPawn Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MenuCamPawn.MenuCamPawn_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void AMenuCamPawn_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MenuCamPawn.MenuCamPawn_C.ReceiveTick
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   DeltaSeconds                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AMenuCamPawn_C::ReceiveTick(float DeltaSeconds)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "ReceiveTick");

	Params::MenuCamPawn_C_ReceiveTick Parms{};

	Parms.DeltaSeconds = DeltaSeconds;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MenuCamPawn.MenuCamPawn_C.OnTeamChange
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   PreviousTeam                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AMenuCamPawn_C::OnTeamChange(int32 PreviousTeam)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "OnTeamChange");

	Params::MenuCamPawn_C_OnTeamChange Parms{};

	Parms.PreviousTeam = PreviousTeam;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MenuCamPawn.MenuCamPawn_C.Animate Move
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void AMenuCamPawn_C::Animate_Move()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "Animate Move");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MenuCamPawn.MenuCamPawn_C.Stop Menu Camera Movement
// (Public, BlueprintCallable, BlueprintEvent)

void AMenuCamPawn_C::Stop_Menu_Camera_Movement()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "Stop Menu Camera Movement");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MenuCamPawn.MenuCamPawn_C.Find Menu Cameras
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void AMenuCamPawn_C::Find_Menu_Cameras()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "Find Menu Cameras");

	UObject::ProcessEvent(Func, nullptr);
}


// Function MenuCamPawn.MenuCamPawn_C.Move Camera
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// EMenuCameraScreen                       New_Camera                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Force                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void AMenuCamPawn_C::Move_Camera(EMenuCameraScreen New_Camera, bool Force)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "Move Camera");

	Params::MenuCamPawn_C_Move_Camera Parms{};

	Parms.New_Camera = New_Camera;
	Parms.Force = Force;

	UObject::ProcessEvent(Func, &Parms);
}


// Function MenuCamPawn.MenuCamPawn_C.GetTeamId
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure, Const)
// Parameters:
// int32                                   ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

int32 AMenuCamPawn_C::GetTeamId() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("MenuCamPawn_C", "GetTeamId");

	Params::MenuCamPawn_C_GetTeamId Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
