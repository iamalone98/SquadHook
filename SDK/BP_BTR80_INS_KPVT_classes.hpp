#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BTR80_INS_KPVT

#include "Basic.hpp"

#include "BP_BTR80_RUS_KPVT_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BTR80_INS_KPVT.BP_BTR80_INS_KPVT_C
// 0x0000 (0x0C10 - 0x0C10)
class ABP_BTR80_INS_KPVT_C final : public ABP_BTR80_RUS_KPVT_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BTR80_INS_KPVT_C">();
	}
	static class ABP_BTR80_INS_KPVT_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BTR80_INS_KPVT_C>();
	}
};
static_assert(alignof(ABP_BTR80_INS_KPVT_C) == 0x000010, "Wrong alignment on ABP_BTR80_INS_KPVT_C");
static_assert(sizeof(ABP_BTR80_INS_KPVT_C) == 0x000C10, "Wrong size on ABP_BTR80_INS_KPVT_C");

}
