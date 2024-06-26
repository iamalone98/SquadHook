#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RoleSelect

#include "Basic.hpp"

#include "W_RoleSelect_classes.hpp"
#include "W_RoleSelect_parameters.hpp"


namespace SDK
{

// Function W_RoleSelect.W_RoleSelect_C.Role Selected__DelegateSignature
// (Public, Delegate, BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Role_Selected__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Role Selected__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.ExecuteUbergraph_W_RoleSelect
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleSelect_C::ExecuteUbergraph_W_RoleSelect(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "ExecuteUbergraph_W_RoleSelect");

	Params::W_RoleSelect_C_ExecuteUbergraph_W_RoleSelect Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.BndEvt__W_RoleListCenter_K2Node_ComponentBoundEvent_1_Roles Refreshed__DelegateSignature
// (BlueprintEvent)

void UW_RoleSelect_C::BndEvt__W_RoleListCenter_K2Node_ComponentBoundEvent_1_Roles_Refreshed__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "BndEvt__W_RoleListCenter_K2Node_ComponentBoundEvent_1_Roles Refreshed__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.OnTick
// (HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// TArray<struct FSQAvailabilityState_Role>In_Player_Role_States                                  (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, ContainsInstancedReference)

void UW_RoleSelect_C::OnTick(const TArray<struct FSQAvailabilityState_Role>& In_Player_Role_States)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "OnTick");

	Params::W_RoleSelect_C_OnTick Parms{};

	Parms.In_Player_Role_States = std::move(In_Player_Role_States);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.New Role Hovered
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRoleSettings*                  Role                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    Hovered                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UW_RoleItem_C*                    Button_Reference                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    bSubRole                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_RoleSelect_C::New_Role_Hovered(class USQRoleSettings* Role, bool Hovered, class UW_RoleItem_C* Button_Reference, bool bSubRole)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "New Role Hovered");

	Params::W_RoleSelect_C_New_Role_Hovered Parms{};

	Parms.Role = Role;
	Parms.Hovered = Hovered;
	Parms.Button_Reference = Button_Reference;
	Parms.bSubRole = bSubRole;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.New Role Selected
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRoleSettings*                  Role                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleSelect_C::New_Role_Selected(class USQRoleSettings* Role)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "New Role Selected");

	Params::W_RoleSelect_C_New_Role_Selected Parms{};

	Parms.Role = Role;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.Destroy R2T
// (BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Destroy_R2T()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Destroy R2T");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Set Role
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRoleSettings*                  New_Role                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleSelect_C::Set_Role(class USQRoleSettings* New_Role)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Set Role");

	Params::W_RoleSelect_C_Set_Role Parms{};

	Parms.New_Role = New_Role;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.Show Current Role
// (BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Show_Current_Role()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Show Current Role");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_RoleSelect_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Draw Role Info
// (BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Draw_Role_Info()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Draw Role Info");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Delay Display Role Info
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRoleSettings*                  RoleReference                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleSelect_C::Delay_Display_Role_Info(class USQRoleSettings* RoleReference)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Delay Display Role Info");

	Params::W_RoleSelect_C_Delay_Display_Role_Info Parms{};

	Parms.RoleReference = RoleReference;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.Set Soldier Material
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UMaterialInterface*               Material                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_RoleSelect_C::Set_Soldier_Material(class UMaterialInterface* Material)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Set Soldier Material");

	Params::W_RoleSelect_C_Set_Soldier_Material Parms{};

	Parms.Material = Material;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_RoleSelect.W_RoleSelect_C.Update Preview State
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Update_Preview_State()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Update Preview State");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Show Deploy Role
// (Public, BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Show_Deploy_Role()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Show Deploy Role");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Create Render Target
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Create_Render_Target()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Create Render Target");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_RoleSelect.W_RoleSelect_C.Update Role Status
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_RoleSelect_C::Update_Role_Status()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_RoleSelect_C", "Update Role Status");

	UObject::ProcessEvent(Func, nullptr);
}

}

