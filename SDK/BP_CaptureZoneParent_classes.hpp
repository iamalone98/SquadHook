#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CaptureZoneParent

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_CaptureZoneParent.BP_CaptureZoneParent_C
// 0x0010 (0x0238 - 0x0228)
class ABP_CaptureZoneParent_C : public AActor
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0228(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_CaptureZoneParent(int32 EntryPoint);
	void Multi_Capture_State_Changed(uint8 Team, uint8 LastTeam);
	void CaptureStateChangeEvent_Event_0(class USQCaptureZoneComponent* CaptureZone, uint8 Team);
	void ReceiveActorBeginOverlap(class AActor* OtherActor);
	void Is_Player_In_Zone(bool* In_Zone);
	void Fog_Of_War_Check(bool* Can_See_Zone_Info);
	void UI_Flag_Animation(uint8 New_Owning_Team, uint8 Last_Owning_Team);
	void Play_Capture_Sound(int32 New_Team_Id, int32 Last_Team_Id);
	void GetCaptureZoneComponent(class USQCaptureZoneComponent** SQCaptureZone);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_CaptureZoneParent_C">();
	}
	static class ABP_CaptureZoneParent_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_CaptureZoneParent_C>();
	}
};
static_assert(alignof(ABP_CaptureZoneParent_C) == 0x000008, "Wrong alignment on ABP_CaptureZoneParent_C");
static_assert(sizeof(ABP_CaptureZoneParent_C) == 0x000238, "Wrong size on ABP_CaptureZoneParent_C");
static_assert(offsetof(ABP_CaptureZoneParent_C, UberGraphFrame) == 0x000228, "Member 'ABP_CaptureZoneParent_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_CaptureZoneParent_C, DefaultSceneRoot) == 0x000230, "Member 'ABP_CaptureZoneParent_C::DefaultSceneRoot' has a wrong offset!");

}

