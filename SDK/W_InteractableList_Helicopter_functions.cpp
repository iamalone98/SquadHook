#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Helicopter

#include "Basic.hpp"

#include "W_InteractableList_Helicopter_classes.hpp"
#include "W_InteractableList_Helicopter_parameters.hpp"


namespace SDK
{

// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.ExecuteUbergraph_W_InteractableList_Helicopter
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Helicopter_C::ExecuteUbergraph_W_InteractableList_Helicopter(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "ExecuteUbergraph_W_InteractableList_Helicopter");

	Params::W_InteractableList_Helicopter_C_ExecuteUbergraph_W_InteractableList_Helicopter Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Helicopter_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Tick");

	Params::W_InteractableList_Helicopter_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Create Interaction Items
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Force                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InteractableList_Helicopter_C::Create_Interaction_Items(bool Force)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Create Interaction Items");

	Params::W_InteractableList_Helicopter_C_Create_Interaction_Items Parms{};

	Parms.Force = Force;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Update Vehicle Claim
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_InteractableList_Helicopter_C::Update_Vehicle_Claim()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Update Vehicle Claim");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Check for Repair Kit
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    bSuccess                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InteractableList_Helicopter_C::Check_for_Repair_Kit(bool* bSuccess)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Check for Repair Kit");

	Params::W_InteractableList_Helicopter_C_Check_for_Repair_Kit Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (bSuccess != nullptr)
		*bSuccess = Parms.bSuccess;
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Interact List
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UVerticalBox*                     Param_InteractList                                     (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Helicopter_C::Get_Interact_List(class UVerticalBox** Param_InteractList)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Get Interact List");

	Params::W_InteractableList_Helicopter_C_Get_Interact_List Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_InteractList != nullptr)
		*Param_InteractList = Parms.Param_InteractList;
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Fade Animation
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidgetAnimation*                 Fade_Animation                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Helicopter_C::Get_Fade_Animation(class UWidgetAnimation** Fade_Animation)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Get Fade Animation");

	Params::W_InteractableList_Helicopter_C_Get_Fade_Animation Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Fade_Animation != nullptr)
		*Fade_Animation = Parms.Fade_Animation;
}


// Function W_InteractableList_Helicopter.W_InteractableList_Helicopter_C.Get Original Offset
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)

void UW_InteractableList_Helicopter_C::Get_Original_Offset()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Helicopter_C", "Get Original Offset");

	UObject::ProcessEvent(Func, nullptr);
}

}
