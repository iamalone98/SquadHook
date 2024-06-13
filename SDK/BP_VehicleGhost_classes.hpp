#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_VehicleGhost

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_SpawnableGhost_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_VehicleGhost.BP_VehicleGhost_C
// 0x0010 (0x02A0 - 0x0290)
class ABP_VehicleGhost_C final : public ABP_SpawnableGhost_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_VehicleGhost_C;                  // 0x0290(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USkeletalMeshComponent*                 PreviewMesh;                                       // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_VehicleGhost(int32 EntryPoint);
	void Spawn();
	void ReceiveBeginPlay();
	void OnLoaded_031AC99D4A39D4B42D8CE89EBD9574C9(TSubclassOf<class UObject> Loaded);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_VehicleGhost_C">();
	}
	static class ABP_VehicleGhost_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_VehicleGhost_C>();
	}
};
static_assert(alignof(ABP_VehicleGhost_C) == 0x000008, "Wrong alignment on ABP_VehicleGhost_C");
static_assert(sizeof(ABP_VehicleGhost_C) == 0x0002A0, "Wrong size on ABP_VehicleGhost_C");
static_assert(offsetof(ABP_VehicleGhost_C, UberGraphFrame_BP_VehicleGhost_C) == 0x000290, "Member 'ABP_VehicleGhost_C::UberGraphFrame_BP_VehicleGhost_C' has a wrong offset!");
static_assert(offsetof(ABP_VehicleGhost_C, PreviewMesh) == 0x000298, "Member 'ABP_VehicleGhost_C::PreviewMesh' has a wrong offset!");

}

