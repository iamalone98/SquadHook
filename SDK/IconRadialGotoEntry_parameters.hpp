#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IconRadialGotoEntry

#include "Basic.hpp"


namespace SDK::Params
{

// Function IconRadialGotoEntry.IconRadialGotoEntry_C.ExecuteUbergraph_IconRadialGotoEntry
// 0x0038 (0x0038 - 0x0000)
struct IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3EA3[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialActionModel_C*                K2Node_DynamicCast_AsBP_Radial_Action_Model;       // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EA4[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialAction_C*                     K2Node_DynamicCast_AsBP_Radial_Action;             // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_CanClick_CanClick;                        // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry) == 0x000008, "Wrong alignment on IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry");
static_assert(sizeof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry) == 0x000038, "Wrong size on IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, EntryPoint) == 0x000000, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::EntryPoint' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, K2Node_DynamicCast_AsBP_Radial_Action_Model) == 0x000010, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::K2Node_DynamicCast_AsBP_Radial_Action_Model' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000020, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, K2Node_DynamicCast_AsBP_Radial_Action) == 0x000028, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::K2Node_DynamicCast_AsBP_Radial_Action' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, K2Node_DynamicCast_bSuccess_1) == 0x000030, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry, CallFunc_CanClick_CanClick) == 0x000031, "Member 'IconRadialGotoEntry_C_ExecuteUbergraph_IconRadialGotoEntry::CallFunc_CanClick_CanClick' has a wrong offset!");

}

