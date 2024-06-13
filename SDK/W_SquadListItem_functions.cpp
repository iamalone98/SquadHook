#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SquadListItem

#include "Basic.hpp"

#include "W_SquadListItem_classes.hpp"
#include "W_SquadListItem_parameters.hpp"


namespace SDK
{

// Function W_SquadListItem.W_SquadListItem_C.ExecuteUbergraph_W_SquadListItem
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::ExecuteUbergraph_W_SquadListItem(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "ExecuteUbergraph_W_SquadListItem");

	Params::W_SquadListItem_C_ExecuteUbergraph_W_SquadListItem Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.On Can Demote Changed TEMP
// (BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::On_Can_Demote_Changed_TEMP()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "On Can Demote Changed TEMP");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnIsCommandSquadChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnIsCommandSquadChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnIsCommandSquadChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__ButtonDemote_K2Node_ComponentBoundEvent_595_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::BndEvt__ButtonDemote_K2Node_ComponentBoundEvent_595_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__ButtonDemote_K2Node_ComponentBoundEvent_595_OnClicked__DelegateSignature");

	Params::W_SquadListItem_C_BndEvt__ButtonDemote_K2Node_ComponentBoundEvent_595_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__Button_Squad_K2Node_ComponentBoundEvent_3_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_SquadListItem_C::BndEvt__Button_Squad_K2Node_ComponentBoundEvent_3_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__Button_Squad_K2Node_ComponentBoundEvent_3_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__Button_Squad_K2Node_ComponentBoundEvent_4_OnButtonHoverEvent__DelegateSignature
// (BlueprintEvent)

void UW_SquadListItem_C::BndEvt__Button_Squad_K2Node_ComponentBoundEvent_4_OnButtonHoverEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__Button_Squad_K2Node_ComponentBoundEvent_4_OnButtonHoverEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Popup Option Return
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   ID                                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UW_PopupOptionBox_C*              ParentPopup                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::Popup_Option_Return(int32 ID, class UW_PopupOptionBox_C* ParentPopup)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Popup Option Return");

	Params::W_SquadListItem_C_Popup_Option_Return Parms{};

	Parms.ID = ID;
	Parms.ParentPopup = ParentPopup;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_SquadListItem_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__ButtonLocked_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::BndEvt__ButtonLocked_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__ButtonLocked_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature");

	Params::W_SquadListItem_C_BndEvt__ButtonLocked_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.Disband Events
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// int32                                   ID                                                     (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UW_PopupOptionBox_C*              ParentPopup                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::Disband_Events(int32 ID, class UW_PopupOptionBox_C* ParentPopup)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Disband Events");

	Params::W_SquadListItem_C_Disband_Events Parms{};

	Parms.ID = ID;
	Parms.ParentPopup = ParentPopup;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__Button_Squad_K2Node_ComponentBoundEvent_5_OnButtonPressedEvent__DelegateSignature
// (BlueprintEvent)

void UW_SquadListItem_C::BndEvt__Button_Squad_K2Node_ComponentBoundEvent_5_OnButtonPressedEvent__DelegateSignature()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__Button_Squad_K2Node_ComponentBoundEvent_5_OnButtonPressedEvent__DelegateSignature");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Create Disband Options
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UW_PopupOptionBox_C*              ParentReference                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::Create_Disband_Options(class UW_PopupOptionBox_C* ParentReference)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Create Disband Options");

	Params::W_SquadListItem_C_Create_Disband_Options Parms{};

	Parms.ParentReference = ParentReference;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.Open Options
// (BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Open_Options()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Open Options");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnSelectionStateChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnSelectionStateChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnSelectionStateChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnListLayoutChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnListLayoutChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnListLayoutChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnJoinButtonStateChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnJoinButtonStateChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnJoinButtonStateChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnIsSelfInSquadChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnIsSelfInSquadChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnIsSelfInSquadChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnMaxMembersChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnMaxMembersChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnMaxMembersChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnMemberNumChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnMemberNumChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnMemberNumChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnLeaderNameChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnLeaderNameChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnLeaderNameChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnSquadNameChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnSquadNameChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnSquadNameChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnSquadIdChanged
// (Event, Protected, BlueprintEvent)

void UW_SquadListItem_C::OnSquadIdChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnSquadIdChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_229_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SquadListItem_C::BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_229_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_229_OnClicked__DelegateSignature");

	Params::W_SquadListItem_C_BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_229_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.Update List Visibility
// (Public, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Update_List_Visibility()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Update List Visibility");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Update Show Fireteams
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Param_Show_Fireteams                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SquadListItem_C::Update_Show_Fireteams(bool Param_Show_Fireteams)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Update Show Fireteams");

	Params::W_SquadListItem_C_Update_Show_Fireteams Parms{};

	Parms.Param_Show_Fireteams = Param_Show_Fireteams;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SquadListItem.W_SquadListItem_C.Clear Selections
// (Public, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Clear_Selections()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Clear Selections");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Toggle Selection State
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Toggle_Selection_State()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Toggle Selection State");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.OnMouseButtonDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UW_SquadListItem_C::OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "OnMouseButtonDown");

	Params::W_SquadListItem_C_OnMouseButtonDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_SquadListItem.W_SquadListItem_C.Update Color
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Update_Color()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Update Color");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Check Member Highlights
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Has_Highlights                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SquadListItem_C::Check_Member_Highlights(bool* Has_Highlights)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Check Member Highlights");

	Params::W_SquadListItem_C_Check_Member_Highlights Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Has_Highlights != nullptr)
		*Has_Highlights = Parms.Has_Highlights;
}


// Function W_SquadListItem.W_SquadListItem_C.Instigator Is In Squad
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Is_In_Squad                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SquadListItem_C::Instigator_Is_In_Squad(bool* Is_In_Squad)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Instigator Is In Squad");

	Params::W_SquadListItem_C_Instigator_Is_In_Squad Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Is_In_Squad != nullptr)
		*Is_In_Squad = Parms.Is_In_Squad;
}


// Function W_SquadListItem.W_SquadListItem_C.Get Selection State
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// ESQSelectionState                       ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

ESQSelectionState UW_SquadListItem_C::Get_Selection_State()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Get Selection State");

	Params::W_SquadListItem_C_Get_Selection_State Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_SquadListItem.W_SquadListItem_C.Check for Self
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Found                                                  (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SquadListItem_C::Check_for_Self(bool* Found)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Check for Self");

	Params::W_SquadListItem_C_Check_for_Self Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Found != nullptr)
		*Found = Parms.Found;
}


// Function W_SquadListItem.W_SquadListItem_C.ToggleMuteAll
// (Public, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::ToggleMuteAll()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "ToggleMuteAll");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Toggle Weapon Setting
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::Toggle_Weapon_Setting()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Toggle Weapon Setting");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.Get_TB_VoteActiveText_Text_0
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UW_SquadListItem_C::Get_TB_VoteActiveText_Text_0()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "Get_TB_VoteActiveText_Text_0");

	Params::W_SquadListItem_C_Get_TB_VoteActiveText_Text_0 Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_SquadListItem.W_SquadListItem_C.SetLeaderName
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_SquadListItem_C::SetLeaderName()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "SetLeaderName");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SquadListItem.W_SquadListItem_C.GetMemberRoot
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// int32                                   FireTeamIndex                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UPanelWidget*                     ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class UPanelWidget* UW_SquadListItem_C::GetMemberRoot(int32 FireTeamIndex) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SquadListItem_C", "GetMemberRoot");

	Params::W_SquadListItem_C_GetMemberRoot Parms{};

	Parms.FireTeamIndex = FireTeamIndex;

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
