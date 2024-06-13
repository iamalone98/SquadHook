#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericDeployableGuidedMissileWeapon

#include "Basic.hpp"

#include "BP_GenericDeployableGuidedMissileWeapon_classes.hpp"
#include "BP_GenericDeployableGuidedMissileWeapon_parameters.hpp"


namespace SDK
{

// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.ExecuteUbergraph_BP_GenericDeployableGuidedMissileWeapon
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::ExecuteUbergraph_BP_GenericDeployableGuidedMissileWeapon(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "ExecuteUbergraph_BP_GenericDeployableGuidedMissileWeapon");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_ExecuteUbergraph_BP_GenericDeployableGuidedMissileWeapon Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.FinishReloadAnim
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::FinishReloadAnim()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "FinishReloadAnim");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.BlueprintOnUnequip
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::BlueprintOnUnequip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "BlueprintOnUnequip");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.CameraOnWeapon
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::CameraOnWeapon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "CameraOnWeapon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.CameraOnSoldier
// (BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::CameraOnSoldier()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "CameraOnSoldier");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.BlueprintOnPreFire
// (Event, Protected, BlueprintCallable, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::BlueprintOnPreFire()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "BlueprintOnPreFire");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.BlueprintOnEquip
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::BlueprintOnEquip()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "BlueprintOnEquip");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.SoldierLeavesVehicle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::SoldierLeavesVehicle(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "SoldierLeavesVehicle");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_SoldierLeavesVehicle Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.SoldierEntersVehicle
// (Event, Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::SoldierEntersVehicle(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "SoldierEntersVehicle");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_SoldierEntersVehicle Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.BlueprintOnReload
// (Event, Protected, BlueprintEvent)

void ABP_GenericDeployableGuidedMissileWeapon_C::BlueprintOnReload()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "BlueprintOnReload");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.BlueprintOnFire
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          Origin                                                 (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ZeroConstructor, ReferenceParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::BlueprintOnFire(const struct FVector& Origin)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "BlueprintOnFire");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_BlueprintOnFire Parms{};

	Parms.Origin = std::move(Origin);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.PlayAnimations
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UAnimMontage*                     TripodAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     WeaponAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     SoldierAnim                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   TripodAnimTime                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   WeaponAnimTime                                         (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   SoldierAnimTime                                        (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::PlayAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, class ASQSoldier* Soldier, float* TripodAnimTime, float* WeaponAnimTime, float* SoldierAnimTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "PlayAnimations");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_PlayAnimations Parms{};

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


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.StopAnimations
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class ASQSoldier*                       Soldier                                                (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::StopAnimations(class ASQSoldier* Soldier)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "StopAnimations");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_StopAnimations Parms{};

	Parms.Soldier = Soldier;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.ResumeAnimations
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UAnimMontage*                     TripodAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     WeaponAnim                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UAnimMontage*                     SoldierAnim                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   AnimDuration                                           (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::ResumeAnimations(class UAnimMontage* TripodAnim, class UAnimMontage* WeaponAnim, class UAnimMontage* SoldierAnim, float* AnimDuration)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "ResumeAnimations");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_ResumeAnimations Parms{};

	Parms.TripodAnim = TripodAnim;
	Parms.WeaponAnim = WeaponAnim;
	Parms.SoldierAnim = SoldierAnim;

	UObject::ProcessEvent(Func, &Parms);

	if (AnimDuration != nullptr)
		*AnimDuration = Parms.AnimDuration;
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.SetReloadAnimTimer
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   Time                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_GenericDeployableGuidedMissileWeapon_C::SetReloadAnimTimer(float Time)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "SetReloadAnimTimer");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_SetReloadAnimTimer Parms{};

	Parms.Time = Time;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.GetPostProcessSettings
// (Event, Protected, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FPostProcessSettings             ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FPostProcessSettings ABP_GenericDeployableGuidedMissileWeapon_C::GetPostProcessSettings()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "GetPostProcessSettings");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_GetPostProcessSettings Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_GenericDeployableGuidedMissileWeapon.BP_GenericDeployableGuidedMissileWeapon_C.GetReticleClass
// (Event, Protected, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// TSubclassOf<class USQVehicleViewWidget> ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash)

TSubclassOf<class USQVehicleViewWidget> ABP_GenericDeployableGuidedMissileWeapon_C::GetReticleClass()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_GenericDeployableGuidedMissileWeapon_C", "GetReticleClass");

	Params::BP_GenericDeployableGuidedMissileWeapon_C_GetReticleClass Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}
