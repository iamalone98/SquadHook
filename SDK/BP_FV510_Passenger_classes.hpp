#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV510_Passenger

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_FV510_Passenger.BP_FV510_Passenger_C
// 0x0020 (0x03F0 - 0x03D0)
class ABP_FV510_Passenger_C final : public ASQVehicleSeat
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x03D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   Viewblock_passenger;                               // 0x03D8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UCameraComponent*                       Camera;                                            // 0x03E0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x03E8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_FV510_Passenger(int32 EntryPoint);
	void InpAxisEvt_Turn_K2Node_InputAxisEvent_39(float AxisValue);
	void InpAxisEvt_LookUp_K2Node_InputAxisEvent_42(float AxisValue);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_FV510_Passenger_C">();
	}
	static class ABP_FV510_Passenger_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_FV510_Passenger_C>();
	}
};
static_assert(alignof(ABP_FV510_Passenger_C) == 0x000010, "Wrong alignment on ABP_FV510_Passenger_C");
static_assert(sizeof(ABP_FV510_Passenger_C) == 0x0003F0, "Wrong size on ABP_FV510_Passenger_C");
static_assert(offsetof(ABP_FV510_Passenger_C, UberGraphFrame) == 0x0003D0, "Member 'ABP_FV510_Passenger_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_FV510_Passenger_C, Viewblock_passenger) == 0x0003D8, "Member 'ABP_FV510_Passenger_C::Viewblock_passenger' has a wrong offset!");
static_assert(offsetof(ABP_FV510_Passenger_C, Camera) == 0x0003E0, "Member 'ABP_FV510_Passenger_C::Camera' has a wrong offset!");
static_assert(offsetof(ABP_FV510_Passenger_C, DefaultSceneRoot) == 0x0003E8, "Member 'ABP_FV510_Passenger_C::DefaultSceneRoot' has a wrong offset!");

}

