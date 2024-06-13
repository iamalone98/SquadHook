#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: FV4034_Ammocook

#include "Basic.hpp"

#include "FV4034_Ammocook_classes.hpp"
#include "FV4034_Ammocook_parameters.hpp"


namespace SDK
{

// Function FV4034_Ammocook.FV4034_Ammocook_C.ExecuteUbergraph_FV4034_Ammocook
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void AFV4034_Ammocook_C::ExecuteUbergraph_FV4034_Ammocook(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FV4034_Ammocook_C", "ExecuteUbergraph_FV4034_Ammocook");

	Params::FV4034_Ammocook_C_ExecuteUbergraph_FV4034_Ammocook Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function FV4034_Ammocook.FV4034_Ammocook_C.BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature
// (HasOutParams, BlueprintEvent)
// Parameters:
// class UPrimitiveComponent*              HitComponent                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class AActor*                           OtherActor                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UPrimitiveComponent*              OtherComp                                              (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FVector                          NormalImpulse                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FHitResult                       Hit                                                    (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, IsPlainOldData, NoDestructor, ContainsInstancedReference)

void AFV4034_Ammocook_C::BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature(class UPrimitiveComponent* HitComponent, class AActor* OtherActor, class UPrimitiveComponent* OtherComp, const struct FVector& NormalImpulse, const struct FHitResult& Hit)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("FV4034_Ammocook_C", "BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature");

	Params::FV4034_Ammocook_C_BndEvt__FV4034_Ammocook_SQVehicleWreckTurretAmmocook_K2Node_ComponentBoundEvent_1_ComponentHitSignature__DelegateSignature Parms{};

	Parms.HitComponent = HitComponent;
	Parms.OtherActor = OtherActor;
	Parms.OtherComp = OtherComp;
	Parms.NormalImpulse = std::move(NormalImpulse);
	Parms.Hit = std::move(Hit);

	UObject::ProcessEvent(Func, &Parms);
}

}

