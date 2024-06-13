#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDeployableWeapon

#include "Basic.hpp"

#include "BP_GenericDeployableWeapon_classes.hpp"
#include "BP_GenericDeployableWeapon_parameters.hpp"


namespace SDK
{

// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.ExecuteUbergraph_BP_GenericDeployableWeapon
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::ExecuteUbergraph_BP_GenericDeployableWeapon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "ExecuteUbergraph_BP_GenericDeployableWeapon");

	Params::BP_GenericDeployableWeapon_C_ExecuteUbergraph_BP_GenericDeployableWeapon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.FinishReloadAnim
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableWeapon_C::FinishReloadAnim()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "FinishReloadAnim");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.BlueprintOnUnequip
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableWeapon_C::BlueprintOnUnequip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "BlueprintOnUnequip");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.CameraOnWeapon
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableWeapon_C::CameraOnWeapon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "CameraOnWeapon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.CameraOnSoldier
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableWeapon_C::CameraOnSoldier()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "CameraOnSoldier");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.SoldierLeavesVehicle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::SoldierLeavesVehicle(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "SoldierLeavesVehicle");

	Params::BP_GenericDeployableWeapon_C_SoldierLeavesVehicle Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.SoldierEntersVehicle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::SoldierEntersVehicle(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "SoldierEntersVehicle");

	Params::BP_GenericDeployableWeapon_C_SoldierEntersVehicle Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.BlueprintOnReload
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableWeapon_C::BlueprintOnReload()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "BlueprintOnReload");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.BlueprintOnFire
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          Origin                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::BlueprintOnFire(const struct FVector& Origin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "BlueprintOnFire");

	Params::BP_GenericDeployableWeapon_C_BlueprintOnFire Parms{};

	Parms.Origin = std::move(Origin);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.BndEvt__SQTemperature_K2Node_ComponentBoundEvent_486_TemperatureIncrementDelegate__DelegateSignature
// (BlueprintEvent)
// Parameters:
// class USQTemperatureComponent*          TriggeringComponent                                    (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   TriggeringTemp                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    bIsLowerTrigger                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_GenericDeployableWeapon_C::BndEvt__SQTemperature_K2Node_ComponentBoundEvent_486_TemperatureIncrementDelegate__DelegateSignature(class USQTemperatureComponent* TriggeringComponent, float TriggeringTemp, bool bIsLowerTrigger)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "BndEvt__SQTemperature_K2Node_ComponentBoundEvent_486_TemperatureIncrementDelegate__DelegateSignature");

	Params::BP_GenericDeployableWeapon_C_BndEvt__SQTemperature_K2Node_ComponentBoundEvent_486_TemperatureIncrementDelegate__DelegateSignature Parms{};

	Parms.TriggeringComponent = TriggeringComponent;
	Parms.TriggeringTemp = TriggeringTemp;
	Parms.bIsLowerTrigger = bIsLowerTrigger;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.PlayAnimations
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UAnimMontage*                     TripodAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     WeaponAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     SoldierAnim                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   TripodAnimTime                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   WeaponAnimTime                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   SoldierAnimTime                                        (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::PlayAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, class ASQSoldier* Soldier, float* TripodAnimTime, float* WeaponAnimTime, float* SoldierAnimTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "PlayAnimations");

	Params::BP_GenericDeployableWeapon_C_PlayAnimations Parms{};

	Parms.TripodAnim = TripodAnim;
	Parms.WeaponAnim = WeaponAnim;
	Parms.SoldierAnim = SoldierAnim;
	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);

	if (TripodAnimTime != nullptr)
		*TripodAnimTime = Parms.TripodAnimTime;

	if (WeaponAnimTime != nullptr)
		*WeaponAnimTime = Parms.WeaponAnimTime;

	if (SoldierAnimTime != nullptr)
		*SoldierAnimTime = Parms.SoldierAnimTime;
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.StopAnimations
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::StopAnimations(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "StopAnimations");

	Params::BP_GenericDeployableWeapon_C_StopAnimations Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.ResumeAnimations
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UAnimMontage*                     TripodAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     WeaponAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     SoldierAnim                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   AnimDuration                                           (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::ResumeAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, float* AnimDuration)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "ResumeAnimations");

	Params::BP_GenericDeployableWeapon_C_ResumeAnimations Parms{};

	Parms.TripodAnim = TripodAnim;
	Parms.WeaponAnim = WeaponAnim;
	Parms.SoldierAnim = SoldierAnim;

	UObject::ProcessEvent(Func, &Parms);

	if (AnimDuration != nullptr)
		*AnimDuration = Parms.AnimDuration;
}


// Function BP_GenericDeployableWeapon.BP_GenericDeployableWeapon_C.SetReloadAnimTimer
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Time                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableWeapon_C::SetReloadAnimTimer(float Time)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableWeapon_C", "SetReloadAnimTimer");

	Params::BP_GenericDeployableWeapon_C_SetReloadAnimTimer Parms{};

	Parms.Time = Time;

	UObject::ProcessEvent(Func, &Parms);
}

}

