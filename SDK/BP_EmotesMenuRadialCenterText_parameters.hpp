#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmotesMenuRadialCenterText

#include "Basic.hpp"


namespace SDK::Params
{

// Function BP_EmotesMenuRadialCenterText.BP_EmotesMenuRadialCenterText_C.ExecuteUbergraph_BP_EmotesMenuRadialCenterText
// 0x0010 (0x0010 - 0x0000)
struct BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3FFD[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBaseRadialMenu_C*                      K2Node_Event_Radial;                               // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText) == 0x000008, "Wrong alignment on BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText");
static_assert(sizeof(BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText) == 0x000010, "Wrong size on BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText");
static_assert(offsetof(BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText, EntryPoint) == 0x000000, "Member 'BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText, K2Node_Event_Radial) == 0x000008, "Member 'BP_EmotesMenuRadialCenterText_C_ExecuteUbergraph_BP_EmotesMenuRadialCenterText::K2Node_Event_Radial' has a wrong offset!");

// Function BP_EmotesMenuRadialCenterText.BP_EmotesMenuRadialCenterText_C.OnClicked
// 0x0008 (0x0008 - 0x0000)
struct BP_EmotesMenuRadialCenterText_C_OnClicked final
{
public:
	class UBaseRadialMenu_C*                      Radial;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_EmotesMenuRadialCenterText_C_OnClicked) == 0x000008, "Wrong alignment on BP_EmotesMenuRadialCenterText_C_OnClicked");
static_assert(sizeof(BP_EmotesMenuRadialCenterText_C_OnClicked) == 0x000008, "Wrong size on BP_EmotesMenuRadialCenterText_C_OnClicked");
static_assert(offsetof(BP_EmotesMenuRadialCenterText_C_OnClicked, Radial) == 0x000000, "Member 'BP_EmotesMenuRadialCenterText_C_OnClicked::Radial' has a wrong offset!");

}
