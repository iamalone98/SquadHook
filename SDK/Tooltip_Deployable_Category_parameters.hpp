#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Tooltip_Deployable_Category

#include "Basic.hpp"


namespace SDK::Params
{

// Function Tooltip_Deployable_Category.Tooltip_Deployable_Category_C.ExecuteUbergraph_Tooltip_Deployable_Category
// 0x0010 (0x0010 - 0x0000)
struct Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F1F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RadialItemModel_C*                  K2Node_Event_In_Outer_Context;                     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category) == 0x000008, "Wrong alignment on Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category");
static_assert(sizeof(Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category) == 0x000010, "Wrong size on Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category");
static_assert(offsetof(Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category, EntryPoint) == 0x000000, "Member 'Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category::EntryPoint' has a wrong offset!");
static_assert(offsetof(Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category, K2Node_Event_In_Outer_Context) == 0x000008, "Member 'Tooltip_Deployable_Category_C_ExecuteUbergraph_Tooltip_Deployable_Category::K2Node_Event_In_Outer_Context' has a wrong offset!");

// Function Tooltip_Deployable_Category.Tooltip_Deployable_Category_C.OnSetContext
// 0x0008 (0x0008 - 0x0000)
struct Tooltip_Deployable_Category_C_OnSetContext final
{
public:
	class UBP_RadialItemModel_C*                  In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(Tooltip_Deployable_Category_C_OnSetContext) == 0x000008, "Wrong alignment on Tooltip_Deployable_Category_C_OnSetContext");
static_assert(sizeof(Tooltip_Deployable_Category_C_OnSetContext) == 0x000008, "Wrong size on Tooltip_Deployable_Category_C_OnSetContext");
static_assert(offsetof(Tooltip_Deployable_Category_C_OnSetContext, In_Outer_Context) == 0x000000, "Member 'Tooltip_Deployable_Category_C_OnSetContext::In_Outer_Context' has a wrong offset!");

}

