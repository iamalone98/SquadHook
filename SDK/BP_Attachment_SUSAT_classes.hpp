#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Attachment_SUSAT

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Attachment_SUSAT.BP_Attachment_SUSAT_C
// 0x0000 (0x05A0 - 0x05A0)
class UBP_Attachment_SUSAT_C final : public USQWeaponAttachment_Scope
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Attachment_SUSAT_C">();
	}
	static class UBP_Attachment_SUSAT_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Attachment_SUSAT_C>();
	}
};
static_assert(alignof(UBP_Attachment_SUSAT_C) == 0x000010, "Wrong alignment on UBP_Attachment_SUSAT_C");
static_assert(sizeof(UBP_Attachment_SUSAT_C) == 0x0005A0, "Wrong size on UBP_Attachment_SUSAT_C");

}

