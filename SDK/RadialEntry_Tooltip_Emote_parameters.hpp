#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialEntry_Tooltip_Emote

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.ExecuteUbergraph_RadialEntry_Tooltip_Emote
// 0x0010 (0x0010 - 0x0000)
struct RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_1C1F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_RadialItemModel_C*                  K2Node_Event_In_Outer_Context;                     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote) == 0x000008, "Wrong alignment on RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote");
static_assert(sizeof(RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote) == 0x000010, "Wrong size on RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote, EntryPoint) == 0x000000, "Member 'RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote::EntryPoint' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote, K2Node_Event_In_Outer_Context) == 0x000008, "Member 'RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote::K2Node_Event_In_Outer_Context' has a wrong offset!");

// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.OnSetContext
// 0x0008 (0x0008 - 0x0000)
struct RadialEntry_Tooltip_Emote_C_OnSetContext final
{
public:
	class UBP_RadialItemModel_C*                  In_Outer_Context;                                  // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialEntry_Tooltip_Emote_C_OnSetContext) == 0x000008, "Wrong alignment on RadialEntry_Tooltip_Emote_C_OnSetContext");
static_assert(sizeof(RadialEntry_Tooltip_Emote_C_OnSetContext) == 0x000008, "Wrong size on RadialEntry_Tooltip_Emote_C_OnSetContext");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_OnSetContext, In_Outer_Context) == 0x000000, "Member 'RadialEntry_Tooltip_Emote_C_OnSetContext::In_Outer_Context' has a wrong offset!");

// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.UpdateDetails
// 0x01A8 (0x01A8 - 0x0000)
struct RadialEntry_Tooltip_Emote_C_UpdateDetails final
{
public:
	class FText                                   Param_Details;                                     // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
	class FName                                   Key_0;                                             // 0x0018(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key_1;                                             // 0x0020(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key_2;                                             // 0x0028(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key2Name;                                          // 0x0030(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key1Name;                                          // 0x0038(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   Key0Name;                                          // 0x0040(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetActionKeyName_Name;                    // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue;            // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1C20[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetActionKeyName_Name_1;                  // 0x0054(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue_1;          // 0x005C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1C21[0x3];                                     // 0x005D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_GetActionKeyName_Name_2;                  // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_NameName_ReturnValue_2;          // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1C22[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_NameToText_ReturnValue;              // 0x0070(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0088(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_NameToText_ReturnValue_1;            // 0x00C8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00E0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_NameToText_ReturnValue_2;            // 0x0120(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x0138(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0178(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0188(0x0018)()
	bool                                          CallFunc_TextIsEmpty_ReturnValue;                  // 0x01A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialEntry_Tooltip_Emote_C_UpdateDetails) == 0x000008, "Wrong alignment on RadialEntry_Tooltip_Emote_C_UpdateDetails");
static_assert(sizeof(RadialEntry_Tooltip_Emote_C_UpdateDetails) == 0x0001A8, "Wrong size on RadialEntry_Tooltip_Emote_C_UpdateDetails");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Param_Details) == 0x000000, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Param_Details' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key_0) == 0x000018, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key_0' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key_1) == 0x000020, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key_1' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key_2) == 0x000028, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key_2' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key2Name) == 0x000030, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key2Name' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key1Name) == 0x000038, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key1Name' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, Key0Name) == 0x000040, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::Key0Name' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_GetActionKeyName_Name) == 0x000048, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_GetActionKeyName_Name' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue) == 0x000050, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_GetActionKeyName_Name_1) == 0x000054, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_GetActionKeyName_Name_1' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue_1) == 0x00005C, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_GetActionKeyName_Name_2) == 0x000060, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_GetActionKeyName_Name_2' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_NotEqual_NameName_ReturnValue_2) == 0x000068, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_NotEqual_NameName_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue) == 0x000070, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData) == 0x000088, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue_1) == 0x0000C8, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000E0, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_Conv_NameToText_ReturnValue_2) == 0x000120, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_Conv_NameToText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, K2Node_MakeStruct_FormatArgumentData_2) == 0x000138, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, K2Node_MakeArray_Array) == 0x000178, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_Format_ReturnValue) == 0x000188, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialEntry_Tooltip_Emote_C_UpdateDetails, CallFunc_TextIsEmpty_ReturnValue) == 0x0001A0, "Member 'RadialEntry_Tooltip_Emote_C_UpdateDetails::CallFunc_TextIsEmpty_ReturnValue' has a wrong offset!");

}
