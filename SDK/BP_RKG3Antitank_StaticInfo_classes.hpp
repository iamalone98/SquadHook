#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RKG3Antitank_StaticInfo

#include "Basic.hpp"

#include "BP_GenericGrenade_StaticInfo_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RKG3Antitank_StaticInfo.BP_RKG3Antitank_StaticInfo_C
// 0x0000 (0x0670 - 0x0670)
class UBP_RKG3Antitank_StaticInfo_C final : public UBP_GenericGrenade_StaticInfo_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RKG3Antitank_StaticInfo_C">();
	}
	static class UBP_RKG3Antitank_StaticInfo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_RKG3Antitank_StaticInfo_C>();
	}
};
static_assert(alignof(UBP_RKG3Antitank_StaticInfo_C) == 0x000008, "Wrong alignment on UBP_RKG3Antitank_StaticInfo_C");
static_assert(sizeof(UBP_RKG3Antitank_StaticInfo_C) == 0x000670, "Wrong size on UBP_RKG3Antitank_StaticInfo_C");

}

