#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InputBackup_PopUp

#include "Basic.hpp"

#include "W_InputBackup_PopUp_classes.hpp"
#include "W_InputBackup_PopUp_parameters.hpp"


namespace SDK
{

// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.ExecuteUbergraph_W_InputBackup_PopUp
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::ExecuteUbergraph_W_InputBackup_PopUp(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "ExecuteUbergraph_W_InputBackup_PopUp");

	Params::W_InputBackup_PopUp_C_ExecuteUbergraph_W_InputBackup_PopUp Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_InputBackup_PopUp_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__ComboBoxString_AvailableOptions_K2Node_ComponentBoundEvent_0_OnSelectionChangedEvent__DelegateSignature
// (BlueprintEvent)
// Parameters:
// class FString                           SelectedItem                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
// ESelectInfo                             SelectionType                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::BndEvt__ComboBoxString_AvailableOptions_K2Node_ComponentBoundEvent_0_OnSelectionChangedEvent__DelegateSignature(const class FString& SelectedItem, ESelectInfo SelectionType)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__ComboBoxString_AvailableOptions_K2Node_ComponentBoundEvent_0_OnSelectionChangedEvent__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__ComboBoxString_AvailableOptions_K2Node_ComponentBoundEvent_0_OnSelectionChangedEvent__DelegateSignature Parms{};

	Parms.SelectedItem = std::move(SelectedItem);
	Parms.SelectionType = SelectionType;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.ChallengeConfirmDelete
// (BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::ChallengeConfirmDelete()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "ChallengeConfirmDelete");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.ChallengeCancelDelete
// (BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::ChallengeCancelDelete()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "ChallengeCancelDelete");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__Button_Save_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::BndEvt__Button_Save_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__Button_Save_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__Button_Save_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__Button_Cancel_K2Node_ComponentBoundEvent_3_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__Button_Delete_K2Node_ComponentBoundEvent_4_OnClicked__DelegateSignature
// (BlueprintEvent)
// Parameters:
// bool                                    bSelected                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
// class UMainMenu_Button_C*               Button                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::BndEvt__Button_Delete_K2Node_ComponentBoundEvent_4_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__Button_Delete_K2Node_ComponentBoundEvent_4_OnClicked__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__Button_Delete_K2Node_ComponentBoundEvent_4_OnClicked__DelegateSignature Parms{};

	Parms.bSelected = bSelected;
	Parms.Button = Button;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "Tick");

	Params::W_InputBackup_PopUp_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_6_OnEditableTextBoxCommittedEvent__DelegateSignature
// (HasOutParams, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// ETextCommit                             CommitMethod                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_6_OnEditableTextBoxCommittedEvent__DelegateSignature(const class FText& Text, ETextCommit CommitMethod)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_6_OnEditableTextBoxCommittedEvent__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_6_OnEditableTextBoxCommittedEvent__DelegateSignature Parms{};

	Parms.Text = std::move(Text);
	Parms.CommitMethod = CommitMethod;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_5_OnEditableTextBoxChangedEvent__DelegateSignature
// (HasOutParams, BlueprintEvent)
// Parameters:
// class FText                             Text                                                   (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)

void UW_InputBackup_PopUp_C::BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_5_OnEditableTextBoxChangedEvent__DelegateSignature(const class FText& Text)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_5_OnEditableTextBoxChangedEvent__DelegateSignature");

	Params::W_InputBackup_PopUp_C_BndEvt__EditableTextBox_Filename_K2Node_ComponentBoundEvent_5_OnEditableTextBoxChangedEvent__DelegateSignature Parms{};

	Parms.Text = std::move(Text);

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.ClearPopup
// (BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::ClearPopup()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "ClearPopup");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.RefreshList
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::RefreshList()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "RefreshList");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.GetSize
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FVector2D                        Size                                                   (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InputBackup_PopUp_C::GetSize(struct FVector2D* Size)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "GetSize");

	Params::W_InputBackup_PopUp_C_GetSize Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Size != nullptr)
		*Size = std::move(Parms.Size);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.CheckSelected
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FString                           Selected                                               (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
// bool                                    CanLoad                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InputBackup_PopUp_C::CheckSelected(const class FString& Selected, bool* CanLoad)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "CheckSelected");

	Params::W_InputBackup_PopUp_C_CheckSelected Parms{};

	Parms.Selected = std::move(Selected);

	UObject::ProcessEvent(Func, &Parms);

	if (CanLoad != nullptr)
		*CanLoad = Parms.CanLoad;
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.DeletePreset
// (Public, BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::DeletePreset()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "DeletePreset");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.ChallengeDeletePreset
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::ChallengeDeletePreset()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "ChallengeDeletePreset");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.LoadBackup
// (Public, BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::LoadBackup()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "LoadBackup");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InputBackup_PopUp.W_InputBackup_PopUp_C.SaveBackup
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_InputBackup_PopUp_C::SaveBackup()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InputBackup_PopUp_C", "SaveBackup");

	UObject::ProcessEvent(Func, nullptr);
}

}
