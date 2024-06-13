#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MarkerRadialEntry

#include "Basic.hpp"


namespace SDK::Params
{

// Function MarkerRadialEntry.MarkerRadialEntry_C.ExecuteUbergraph_MarkerRadialEntry
// 0x0068 (0x0068 - 0x0000)
struct MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_MapMarkersEnabledDefined_ReturnValue;     // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E9E[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_PlaceMarkerActionModel_C*           K2Node_DynamicCast_AsBP_Place_Marker_Action_Model; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E9F[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialActionModel_C*                K2Node_DynamicCast_AsBP_Radial_Action_Model;       // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EA0[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_SpottedMapMarker_C*                 K2Node_DynamicCast_AsBP_Spotted_Map_Marker;        // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EA1[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue_1;        // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialAction_C*                     K2Node_DynamicCast_AsBP_Radial_Action;             // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3EA2[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_CanClick_CanClick;                        // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry) == 0x000008, "Wrong alignment on MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry");
static_assert(sizeof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry) == 0x000068, "Wrong size on MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, EntryPoint) == 0x000000, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::EntryPoint' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, CallFunc_MapMarkersEnabledDefined_ReturnValue) == 0x000004, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::CallFunc_MapMarkersEnabledDefined_ReturnValue' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_AsBP_Place_Marker_Action_Model) == 0x000008, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_AsBP_Place_Marker_Action_Model' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000018, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_AsBP_Radial_Action_Model) == 0x000020, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_AsBP_Radial_Action_Model' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_bSuccess_1) == 0x000028, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_AsBP_Spotted_Map_Marker) == 0x000030, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_AsBP_Spotted_Map_Marker' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_bSuccess_2) == 0x000038, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, CallFunc_GetDefaultObjectFor_ReturnValue_1) == 0x000040, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::CallFunc_GetDefaultObjectFor_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_AsBP_Radial_Action) == 0x000048, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_AsBP_Radial_Action' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, K2Node_DynamicCast_bSuccess_3) == 0x000050, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, CallFunc_GetOwningPlayer_ReturnValue) == 0x000058, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry, CallFunc_CanClick_CanClick) == 0x000060, "Member 'MarkerRadialEntry_C_ExecuteUbergraph_MarkerRadialEntry::CallFunc_CanClick_CanClick' has a wrong offset!");

}

