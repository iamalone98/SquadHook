#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RequestPickUp_Marker

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_SpottedMapMarker_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RequestPickUp_Marker.BP_RequestPickUp_Marker_C
// 0x0008 (0x0288 - 0x0280)
class ABP_RequestPickUp_Marker_C final : public ABP_SpottedMapMarker_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_RequestPickUp_Marker_C;          // 0x0280(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_RequestPickUp_Marker(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RequestPickUp_Marker_C">();
	}
	static class ABP_RequestPickUp_Marker_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RequestPickUp_Marker_C>();
	}
};
static_assert(alignof(ABP_RequestPickUp_Marker_C) == 0x000008, "Wrong alignment on ABP_RequestPickUp_Marker_C");
static_assert(sizeof(ABP_RequestPickUp_Marker_C) == 0x000288, "Wrong size on ABP_RequestPickUp_Marker_C");
static_assert(offsetof(ABP_RequestPickUp_Marker_C, UberGraphFrame_BP_RequestPickUp_Marker_C) == 0x000280, "Member 'ABP_RequestPickUp_Marker_C::UberGraphFrame_BP_RequestPickUp_Marker_C' has a wrong offset!");

}

