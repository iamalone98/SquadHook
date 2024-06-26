#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_VehicleSmoke_Proj

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_40MM_Proj2_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_VehicleSmoke_Proj.BP_VehicleSmoke_Proj_C
// 0x0038 (0x0578 - 0x0540)
class ABP_VehicleSmoke_Proj_C final : public ABP_40MM_Proj2_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_VehicleSmoke_Proj_C;             // 0x0540(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQVehicleSmokeComponent*               SQVehicleSmoke;                                    // 0x0548(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               Effect;                                            // 0x0550(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        SmokeEffect;                                       // 0x0558(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 LastingEffect;                                     // 0x0560(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         TotalAngle;                                        // 0x0568(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         NumSpheres;                                        // 0x056C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SphereRadius;                                      // 0x0570(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_VehicleSmoke_Proj(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_VehicleSmoke_Proj_C">();
	}
	static class ABP_VehicleSmoke_Proj_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_VehicleSmoke_Proj_C>();
	}
};
static_assert(alignof(ABP_VehicleSmoke_Proj_C) == 0x000008, "Wrong alignment on ABP_VehicleSmoke_Proj_C");
static_assert(sizeof(ABP_VehicleSmoke_Proj_C) == 0x000578, "Wrong size on ABP_VehicleSmoke_Proj_C");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, UberGraphFrame_BP_VehicleSmoke_Proj_C) == 0x000540, "Member 'ABP_VehicleSmoke_Proj_C::UberGraphFrame_BP_VehicleSmoke_Proj_C' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, SQVehicleSmoke) == 0x000548, "Member 'ABP_VehicleSmoke_Proj_C::SQVehicleSmoke' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, Effect) == 0x000550, "Member 'ABP_VehicleSmoke_Proj_C::Effect' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, SmokeEffect) == 0x000558, "Member 'ABP_VehicleSmoke_Proj_C::SmokeEffect' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, LastingEffect) == 0x000560, "Member 'ABP_VehicleSmoke_Proj_C::LastingEffect' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, TotalAngle) == 0x000568, "Member 'ABP_VehicleSmoke_Proj_C::TotalAngle' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, NumSpheres) == 0x00056C, "Member 'ABP_VehicleSmoke_Proj_C::NumSpheres' has a wrong offset!");
static_assert(offsetof(ABP_VehicleSmoke_Proj_C, SphereRadius) == 0x000570, "Member 'ABP_VehicleSmoke_Proj_C::SphereRadius' has a wrong offset!");

}

