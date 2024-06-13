#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_DeployableGhost

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_SpawnableGhost_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_DeployableGhost.BP_DeployableGhost_C
// 0x0010 (0x02A0 - 0x0290)
class ABP_DeployableGhost_C final : public ABP_SpawnableGhost_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_DeployableGhost_C;               // 0x0290(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQDeployableGhostChildActorComp*       SQDeployableGhostChildActorComp;                   // 0x0298(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_DeployableGhost(int32 EntryPoint);
	void Spawn();
	void ReceiveBeginPlay();
	void OnLoaded_ADD952194FEA03C93E994296421D683E(TSubclassOf<class UObject> Loaded);
	void GetFinalTransform(struct FTransform* Transform);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_DeployableGhost_C">();
	}
	static class ABP_DeployableGhost_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_DeployableGhost_C>();
	}
};
static_assert(alignof(ABP_DeployableGhost_C) == 0x000008, "Wrong alignment on ABP_DeployableGhost_C");
static_assert(sizeof(ABP_DeployableGhost_C) == 0x0002A0, "Wrong size on ABP_DeployableGhost_C");
static_assert(offsetof(ABP_DeployableGhost_C, UberGraphFrame_BP_DeployableGhost_C) == 0x000290, "Member 'ABP_DeployableGhost_C::UberGraphFrame_BP_DeployableGhost_C' has a wrong offset!");
static_assert(offsetof(ABP_DeployableGhost_C, SQDeployableGhostChildActorComp) == 0x000298, "Member 'ABP_DeployableGhost_C::SQDeployableGhostChildActorComp' has a wrong offset!");

}
