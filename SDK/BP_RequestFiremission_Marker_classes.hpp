#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RequestFiremission_Marker

#include "Basic.hpp"

#include "BP_SpottedMapMarker_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RequestFiremission_Marker.BP_RequestFiremission_Marker_C
// 0x0000 (0x0280 - 0x0280)
class ABP_RequestFiremission_Marker_C final : public ABP_SpottedMapMarker_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RequestFiremission_Marker_C">();
	}
	static class ABP_RequestFiremission_Marker_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_RequestFiremission_Marker_C>();
	}
};
static_assert(alignof(ABP_RequestFiremission_Marker_C) == 0x000008, "Wrong alignment on ABP_RequestFiremission_Marker_C");
static_assert(sizeof(ABP_RequestFiremission_Marker_C) == 0x000280, "Wrong size on ABP_RequestFiremission_Marker_C");

}
