#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_FV510UA

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_FV510_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_FV510UA.BP_FV510UA_C
// 0x0010 (0x0C00 - 0x0BF0)
class ABP_FV510UA_C final : public ABP_FV510_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_FV510UA_C;                       // 0x0BF0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UStaticMeshComponent*                   FV510_UA_Collision;                                // 0x0BF8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_FV510UA(int32 EntryPoint);
	void DrivetrainComponentRepaired(class USQDriveTrainComponent* DriveTrainComponent);
	void DrivetrainComponentDestroyed(class USQDriveTrainComponent* DriveTrainComponent);
	void Update_Damaged_Track_Visual_Minus_FV510UA(class UObject* VehicleTrack, bool bIsTrackDestroyed, bool ShowOriginalTrack);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_FV510UA_C">();
	}
	static class ABP_FV510UA_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_FV510UA_C>();
	}
};
static_assert(alignof(ABP_FV510UA_C) == 0x000010, "Wrong alignment on ABP_FV510UA_C");
static_assert(sizeof(ABP_FV510UA_C) == 0x000C00, "Wrong size on ABP_FV510UA_C");
static_assert(offsetof(ABP_FV510UA_C, UberGraphFrame_BP_FV510UA_C) == 0x000BF0, "Member 'ABP_FV510UA_C::UberGraphFrame_BP_FV510UA_C' has a wrong offset!");
static_assert(offsetof(ABP_FV510UA_C, FV510_UA_Collision) == 0x000BF8, "Member 'ABP_FV510UA_C::FV510_UA_Collision' has a wrong offset!");

}

