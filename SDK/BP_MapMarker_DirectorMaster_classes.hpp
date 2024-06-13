#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_DirectorMaster

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_GenericMapMarker_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_MapMarker_DirectorMaster.BP_MapMarker_DirectorMaster_C
// 0x0010 (0x0290 - 0x0280)
class ABP_MapMarker_DirectorMaster_C : public ABP_GenericMapMarker_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_MapMarker_DirectorMaster_C;      // 0x0280(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	float                                         Distance;                                          // 0x0288(0x0004)(Edit, BlueprintVisible, Net, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MapMarker_DirectorMaster(int32 EntryPoint);
	void ReceiveBeginPlay();
	void OnDestroyed_Event_0(class AActor* DestroyedActor);
	void Bind_To_Destroy(class AActor* Bind_To);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapMarker_DirectorMaster_C">();
	}
	static class ABP_MapMarker_DirectorMaster_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_MapMarker_DirectorMaster_C>();
	}
};
static_assert(alignof(ABP_MapMarker_DirectorMaster_C) == 0x000008, "Wrong alignment on ABP_MapMarker_DirectorMaster_C");
static_assert(sizeof(ABP_MapMarker_DirectorMaster_C) == 0x000290, "Wrong size on ABP_MapMarker_DirectorMaster_C");
static_assert(offsetof(ABP_MapMarker_DirectorMaster_C, UberGraphFrame_BP_MapMarker_DirectorMaster_C) == 0x000280, "Member 'ABP_MapMarker_DirectorMaster_C::UberGraphFrame_BP_MapMarker_DirectorMaster_C' has a wrong offset!");
static_assert(offsetof(ABP_MapMarker_DirectorMaster_C, Distance) == 0x000288, "Member 'ABP_MapMarker_DirectorMaster_C::Distance' has a wrong offset!");

}
