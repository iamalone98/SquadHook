#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialEntry_Tooltip

#include "Basic.hpp"


namespace SDK::Params
{

// Function RadialEntry_Tooltip.RadialEntry_Tooltip_C.ExecuteUbergraph_RadialEntry_Tooltip
// 0x0010 (0x0010 - 0x0000)
struct RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F1E[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RadialItemModel_C*                  K2Node_CustomEvent_In_Outer_Context;               // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip) == 0x000008, "Wrong alignment on RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip");
static_assert(sizeof(RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip) == 0x000010, "Wrong size on RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip");
static_assert(offsetof(RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip, EntryPoint) == 0x000000, "Member 'RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip::EntryPoint' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip, K2Node_CustomEvent_In_Outer_Context) == 0x000008, "Member 'RadialEntry_Tooltip_C_ExecuteUbergraph_RadialEntry_Tooltip::K2Node_CustomEvent_In_Outer_Context' has a wrong offset!");

// Function RadialEntry_Tooltip.RadialEntry_Tooltip_C.OnSetContext
// 0x0008 (0x0008 - 0x0000)
struct RadialEntry_Tooltip_C_OnSetContext final
{
public:
	class UBP_RadialItemModel_C*                  In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialEntry_Tooltip_C_OnSetContext) == 0x000008, "Wrong alignment on RadialEntry_Tooltip_C_OnSetContext");
static_assert(sizeof(RadialEntry_Tooltip_C_OnSetContext) == 0x000008, "Wrong size on RadialEntry_Tooltip_C_OnSetContext");
static_assert(offsetof(RadialEntry_Tooltip_C_OnSetContext, In_Outer_Context) == 0x000000, "Member 'RadialEntry_Tooltip_C_OnSetContext::In_Outer_Context' has a wrong offset!");

}
