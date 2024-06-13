#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Deployable

#include "Basic.hpp"

#include "W_InteractableList_Deployable_classes.hpp"
#include "W_InteractableList_Deployable_parameters.hpp"


namespace SDK
{

// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.ExecuteUbergraph_W_InteractableList_Deployable
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Deployable_C::ExecuteUbergraph_W_InteractableList_Deployable(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "ExecuteUbergraph_W_InteractableList_Deployable");

	Params::W_InteractableList_Deployable_C_ExecuteUbergraph_W_InteractableList_Deployable Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Set Custom Data
// (BlueprintCallable, BlueprintEvent)

void UW_InteractableList_Deployable_C::Set_Custom_Data()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Set Custom Data");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Soldier Has Shovel
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Shovel_Equipped                                        (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    Owns_Shovel                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InteractableList_Deployable_C::Soldier_Has_Shovel(bool* Shovel_Equipped, bool* Owns_Shovel)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Soldier Has Shovel");

	Params::W_InteractableList_Deployable_C_Soldier_Has_Shovel Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Shovel_Equipped != nullptr)
		*Shovel_Equipped = Parms.Shovel_Equipped;

	if (Owns_Shovel != nullptr)
		*Owns_Shovel = Parms.Owns_Shovel;
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Is Deployable Built
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    Is_Built                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    Full_Health                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
// bool                                    bCanUnbuild                                            (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InteractableList_Deployable_C::Is_Deployable_Built(bool* Is_Built, bool* Full_Health, bool* bCanUnbuild)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Is Deployable Built");

	Params::W_InteractableList_Deployable_C_Is_Deployable_Built Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Is_Built != nullptr)
		*Is_Built = Parms.Is_Built;

	if (Full_Health != nullptr)
		*Full_Health = Parms.Full_Health;

	if (bCanUnbuild != nullptr)
		*bCanUnbuild = Parms.bCanUnbuild;
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Create Contextual Data
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Force_Update                                           (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_InteractableList_Deployable_C::Create_Contextual_Data(bool* Force_Update)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Create Contextual Data");

	Params::W_InteractableList_Deployable_C_Create_Contextual_Data Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Force_Update != nullptr)
		*Force_Update = Parms.Force_Update;
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Same Team
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UW_InteractableList_Deployable_C::Same_Team()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Same Team");

	Params::W_InteractableList_Deployable_C_Same_Team Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Deployable_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Tick");

	Params::W_InteractableList_Deployable_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Get Interact List
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UVerticalBox*                     Param_InteractList                                     (Parm, OutParm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Deployable_C::Get_Interact_List(class UVerticalBox** Param_InteractList)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Get Interact List");

	Params::W_InteractableList_Deployable_C_Get_Interact_List Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Param_InteractList != nullptr)
		*Param_InteractList = Parms.Param_InteractList;
}


// Function W_InteractableList_Deployable.W_InteractableList_Deployable_C.Get Fade Animation
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class UWidgetAnimation*                 Fade_Animation                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_InteractableList_Deployable_C::Get_Fade_Animation(class UWidgetAnimation** Fade_Animation)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_InteractableList_Deployable_C", "Get Fade Animation");

	Params::W_InteractableList_Deployable_C_Get_Fade_Animation Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Fade_Animation != nullptr)
		*Fade_Animation = Parms.Fade_Animation;
}

}

