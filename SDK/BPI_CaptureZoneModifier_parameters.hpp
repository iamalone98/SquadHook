#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPI_CaptureZoneModifier

#include "Basic.hpp"


namespace SDK::Params
{

// Function BPI_CaptureZoneModifier.BPI_CaptureZoneModifier_C.Additional Can Capture
// 0x0001 (0x0001 - 0x0000)
struct BPI_CaptureZoneModifier_C_Additional_Can_Capture final
{
public:
	bool                                          Can_Capture;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BPI_CaptureZoneModifier_C_Additional_Can_Capture) == 0x000001, "Wrong alignment on BPI_CaptureZoneModifier_C_Additional_Can_Capture");
static_assert(sizeof(BPI_CaptureZoneModifier_C_Additional_Can_Capture) == 0x000001, "Wrong size on BPI_CaptureZoneModifier_C_Additional_Can_Capture");
static_assert(offsetof(BPI_CaptureZoneModifier_C_Additional_Can_Capture, Can_Capture) == 0x000000, "Member 'BPI_CaptureZoneModifier_C_Additional_Can_Capture::Can_Capture' has a wrong offset!");

}

