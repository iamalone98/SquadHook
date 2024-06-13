#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CaptureZone

#include "Basic.hpp"

#include "BP_CaptureZoneParent_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_CaptureZone.BP_CaptureZone_C
// 0x0008 (0x0240 - 0x0238)
class ABP_CaptureZone_C final : public ABP_CaptureZoneParent_C
{
public:
	class USQCaptureZoneComponent*                SQCaptureZone;                                     // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void GetCaptureZoneComponent(class USQCaptureZoneComponent** Param_SQCaptureZone);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_CaptureZone_C">();
	}
	static class ABP_CaptureZone_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_CaptureZone_C>();
	}
};
static_assert(alignof(ABP_CaptureZone_C) == 0x000008, "Wrong alignment on ABP_CaptureZone_C");
static_assert(sizeof(ABP_CaptureZone_C) == 0x000240, "Wrong size on ABP_CaptureZone_C");
static_assert(offsetof(ABP_CaptureZone_C, SQCaptureZone) == 0x000238, "Member 'ABP_CaptureZone_C::SQCaptureZone' has a wrong offset!");

}

