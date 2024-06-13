#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Legend_LayerInfo

#include "Basic.hpp"

#include "S_FOBRadius_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.ExecuteUbergraph_W_Legend_LayerInfo
// 0x0004 (0x0004 - 0x0000)
struct W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo) == 0x000004, "Wrong alignment on W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo");
static_assert(sizeof(W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo) == 0x000004, "Wrong size on W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo");
static_assert(offsetof(W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo, EntryPoint) == 0x000000, "Member 'W_Legend_LayerInfo_C_ExecuteUbergraph_W_Legend_LayerInfo::EntryPoint' has a wrong offset!");

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.GetFOBExclusionRadius
// 0x00B8 (0x00B8 - 0x0000)
struct W_Legend_LayerInfo_C_GetFOBExclusionRadius final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46DF[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x0028(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46E0[0x3];                                     // 0x0049(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0050(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0090(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00A0(0x0018)()
};
static_assert(alignof(W_Legend_LayerInfo_C_GetFOBExclusionRadius) == 0x000008, "Wrong alignment on W_Legend_LayerInfo_C_GetFOBExclusionRadius");
static_assert(sizeof(W_Legend_LayerInfo_C_GetFOBExclusionRadius) == 0x0000B8, "Wrong size on W_Legend_LayerInfo_C_GetFOBExclusionRadius");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, ReturnValue) == 0x000000, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000018, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000020, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_GetDataTableRowFromName_OutRow) == 0x000028, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000048, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00004C, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, K2Node_MakeStruct_FormatArgumentData) == 0x000050, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, K2Node_MakeArray_Array) == 0x000090, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBExclusionRadius, CallFunc_Format_ReturnValue) == 0x0000A0, "Member 'W_Legend_LayerInfo_C_GetFOBExclusionRadius::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.Get_HorizontalBox_ToolTipWidget
// 0x0018 (0x0018 - 0x0000)
struct W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget final
{
public:
	class UWidget*                                ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_Tooltip_C*                         CallFunc_Create_ReturnValue;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget) == 0x000008, "Wrong alignment on W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget");
static_assert(sizeof(W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget) == 0x000018, "Wrong size on W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget, ReturnValue) == 0x000000, "Member 'W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget, CallFunc_Create_ReturnValue) == 0x000010, "Member 'W_Legend_LayerInfo_C_Get_HorizontalBox_ToolTipWidget::CallFunc_Create_ReturnValue' has a wrong offset!");

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.Get_FOBConstructionRadius_ToolTipWidget_0
// 0x0018 (0x0018 - 0x0000)
struct W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0 final
{
public:
	class UWidget*                                ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_Tooltip_C*                         CallFunc_Create_ReturnValue;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0) == 0x000008, "Wrong alignment on W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0");
static_assert(sizeof(W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0) == 0x000018, "Wrong size on W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0, ReturnValue) == 0x000000, "Member 'W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0, CallFunc_Create_ReturnValue) == 0x000010, "Member 'W_Legend_LayerInfo_C_Get_FOBConstructionRadius_ToolTipWidget_0::CallFunc_Create_ReturnValue' has a wrong offset!");

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.Get_HabProxyRadius_ToolTipWidget_0
// 0x0018 (0x0018 - 0x0000)
struct W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0 final
{
public:
	class UWidget*                                ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_Tooltip_C*                         CallFunc_Create_ReturnValue;                       // 0x0010(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0) == 0x000008, "Wrong alignment on W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0");
static_assert(sizeof(W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0) == 0x000018, "Wrong size on W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0, ReturnValue) == 0x000000, "Member 'W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0, CallFunc_Create_ReturnValue) == 0x000010, "Member 'W_Legend_LayerInfo_C_Get_HabProxyRadius_ToolTipWidget_0::CallFunc_Create_ReturnValue' has a wrong offset!");

// Function W_Legend_LayerInfo.W_Legend_LayerInfo_C.GetFOBConstructionRadius
// 0x00B8 (0x00B8 - 0x0000)
struct W_Legend_LayerInfo_C_GetFOBConstructionRadius final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46E1[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x0028(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46E2[0x3];                                     // 0x0049(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0050(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0090(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00A0(0x0018)()
};
static_assert(alignof(W_Legend_LayerInfo_C_GetFOBConstructionRadius) == 0x000008, "Wrong alignment on W_Legend_LayerInfo_C_GetFOBConstructionRadius");
static_assert(sizeof(W_Legend_LayerInfo_C_GetFOBConstructionRadius) == 0x0000B8, "Wrong size on W_Legend_LayerInfo_C_GetFOBConstructionRadius");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, ReturnValue) == 0x000000, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000018, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000020, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_GetDataTableRowFromName_OutRow) == 0x000028, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000048, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00004C, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, K2Node_MakeStruct_FormatArgumentData) == 0x000050, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, K2Node_MakeArray_Array) == 0x000090, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_Legend_LayerInfo_C_GetFOBConstructionRadius, CallFunc_Format_ReturnValue) == 0x0000A0, "Member 'W_Legend_LayerInfo_C_GetFOBConstructionRadius::CallFunc_Format_ReturnValue' has a wrong offset!");

}
