#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_USBinoculars_StaticInfo

#include "Basic.hpp"

#include "BP_GenericBinoculars_StaticInfo_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_USBinoculars_StaticInfo.BP_USBinoculars_StaticInfo_C
// 0x0000 (0x0D88 - 0x0D88)
class UBP_USBinoculars_StaticInfo_C final : public UBP_GenericBinoculars_StaticInfo_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_USBinoculars_StaticInfo_C">();
	}
	static class UBP_USBinoculars_StaticInfo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_USBinoculars_StaticInfo_C>();
	}
};
static_assert(alignof(UBP_USBinoculars_StaticInfo_C) == 0x000008, "Wrong alignment on UBP_USBinoculars_StaticInfo_C");
static_assert(sizeof(UBP_USBinoculars_StaticInfo_C) == 0x000D88, "Wrong size on UBP_USBinoculars_StaticInfo_C");

}

