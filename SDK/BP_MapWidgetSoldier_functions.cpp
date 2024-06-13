#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetSoldier

#include "Basic.hpp"

#include "BP_MapWidgetSoldier_classes.hpp"
#include "BP_MapWidgetSoldier_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.ExecuteUbergraph_BP_MapWidgetSoldier
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetSoldier_C::ExecuteUbergraph_BP_MapWidgetSoldier(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "ExecuteUbergraph_BP_MapWidgetSoldier");

	Params::BP_MapWidgetSoldier_C_ExecuteUbergraph_BP_MapWidgetSoldier Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsAliveChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsAliveChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsAliveChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnLeaderStateChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnLeaderStateChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnLeaderStateChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnCommanderChangedEvent_Event_0
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQPlayerState*                   OldCommander                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQPlayerState*                   NewCommander                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetSoldier_C::OnCommanderChangedEvent_Event_0(class ASQPlayerState* OldCommander, class ASQPlayerState* NewCommander)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnCommanderChangedEvent_Event_0");

	Params::BP_MapWidgetSoldier_C_OnCommanderChangedEvent_Event_0 Parms{};

	Parms.OldCommander = OldCommander;
	Parms.NewCommander = NewCommander;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsInSelfTeam
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsInSelfTeam()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsInSelfTeam");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsInSelfSquad
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsInSelfSquad()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsInSelfSquad");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnAngleChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnAngleChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnAngleChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnFireTeamIndexChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnFireTeamIndexChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnFireTeamIndexChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnFireteamIdChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnFireteamIdChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnFireteamIdChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsWoundedChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsWoundedChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsWoundedChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetSoldier_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnScaleChanged");

	Params::BP_MapWidgetSoldier_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnCurrentRoleChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnCurrentRoleChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnCurrentRoleChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnSelectionStateChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnSelectionStateChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnSelectionStateChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnSoldierInfoChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnSoldierInfoChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnSoldierInfoChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnCameraRotationYawChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnCameraRotationYawChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnCameraRotationYawChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnSquadIdChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnSquadIdChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnSquadIdChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsInVehicleChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsInVehicleChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsInVehicleChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsOwnedBySelfChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsOwnedBySelfChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsOwnedBySelfChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnIsMedicChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnIsMedicChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnIsMedicChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnShowIncapChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnShowIncapChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnShowIncapChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnShowBleedingChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnShowBleedingChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnShowBleedingChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnTintValueChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetSoldier_C::OnTintValueChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnTintValueChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Player Image
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Player_Image()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Player Image");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Icon Size
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Icon_Size()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Icon Size");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Tooltip
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidget*                          ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UWidget* UBP_MapWidgetSoldier_C::Tooltip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Tooltip");

	Params::BP_MapWidgetSoldier_C_Tooltip Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.On_TooltipHitBox_MouseButtonDown_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MapWidgetSoldier_C::On_TooltipHitBox_MouseButtonDown_0(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "On_TooltipHitBox_MouseButtonDown_0");

	Params::BP_MapWidgetSoldier_C_On_TooltipHitBox_MouseButtonDown_0 Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Role Info
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Zoom_Amount                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetSoldier_C::Update_Role_Info(float Zoom_Amount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Role Info");

	Params::BP_MapWidgetSoldier_C_Update_Role_Info Parms{};

	Parms.Zoom_Amount = Zoom_Amount;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Role Icon
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Role_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Role Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Same Fireteam
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Same                                                   (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UBP_MapWidgetSoldier_C::Same_Fireteam(bool* Same)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Same Fireteam");

	Params::BP_MapWidgetSoldier_C_Same_Fireteam Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Same != nullptr)
		*Same = Parms.Same;
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.OnMouseButtonUp
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UBP_MapWidgetSoldier_C::OnMouseButtonUp(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "OnMouseButtonUp");

	Params::BP_MapWidgetSoldier_C_OnMouseButtonUp Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Is Medic Icon
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Is_Medic_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Is Medic Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update ID
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_ID()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update ID");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Wounded Opacity
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Wounded_Opacity()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Wounded Opacity");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Color
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Color()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Color");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Update Tooltip Color
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Update_Tooltip_Color()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Update Tooltip Color");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Set Show Fireteam Letter
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Set_Show_Fireteam_Letter()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Set Show Fireteam Letter");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Refresh Element Visibility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Refresh_Element_Visibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Refresh Element Visibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.Set View Cone Visibility
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::Set_View_Cone_Visibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "Set View Cone Visibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.UpdateVoipAnim
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::UpdateVoipAnim()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "UpdateVoipAnim");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.HandleMapCoreChanged
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::HandleMapCoreChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "HandleMapCoreChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetSoldier.BP_MapWidgetSoldier_C.HandleMapZoom
// (Public, BlueprintCallable, BlueprintEvent)

void UBP_MapWidgetSoldier_C::HandleMapZoom()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetSoldier_C", "HandleMapZoom");

	UObject::ProcessEvent(Func, nullptr);
}

}

