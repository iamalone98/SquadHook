#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: CreditListItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"


namespace SDK::Params
{

// Function CreditListItem.CreditListItem_C.ExecuteUbergraph_CreditListItem
// 0x0004 (0x0004 - 0x0000)
struct CreditListItem_C_ExecuteUbergraph_CreditListItem final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(CreditListItem_C_ExecuteUbergraph_CreditListItem) == 0x000004, "Wrong alignment on CreditListItem_C_ExecuteUbergraph_CreditListItem");
static_assert(sizeof(CreditListItem_C_ExecuteUbergraph_CreditListItem) == 0x000004, "Wrong size on CreditListItem_C_ExecuteUbergraph_CreditListItem");
static_assert(offsetof(CreditListItem_C_ExecuteUbergraph_CreditListItem, EntryPoint) == 0x000000, "Member 'CreditListItem_C_ExecuteUbergraph_CreditListItem::EntryPoint' has a wrong offset!");

// Function CreditListItem.CreditListItem_C.Refresh
// 0x0308 (0x0308 - 0x0000)
struct CreditListItem_C_Refresh final
{
public:
	TArray<class FString>                         New_Columns;                                       // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FSlateChildSize                        K2Node_MakeStruct_SlateChildSize;                  // 0x0010(0x0008)(NoDestructor)
	bool                                          Temp_bool_Variable;                                // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31C2[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable;                     // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x002C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31C3[0x3];                                     // 0x002D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Array_Get_Item;                           // 0x0030(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0040(0x0018)()
	class FString                                 CallFunc_Array_Get_Item_1;                         // 0x0058(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0068(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_1;          // 0x00A8(0x0018)()
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00C0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31C4[0x4];                                     // 0x00C4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00C8(0x0040)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0108(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_2;               // 0x010C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0110(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0111(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_SwitchInteger_CmpSuccess;                   // 0x0112(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31C5[0x5];                                     // 0x0113(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class UHorizontalBoxSlot*                     CallFunc_SlotAsHorizontalBoxSlot_ReturnValue;      // 0x0118(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UHorizontalBoxSlot*                     CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_1;    // 0x0120(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_MakeLiteralText_ReturnValue;              // 0x0128(0x0018)()
	class FText                                   CallFunc_GetText_ReturnValue;                      // 0x0140(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x0158(0x0040)(HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_3;            // 0x0198(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x01D8(0x0010)(ReferenceParm)
	class UHorizontalBoxSlot*                     CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_2;    // 0x01E8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x01F0(0x0018)()
	class FText                                   CallFunc_MakeLiteralText_ReturnValue_1;            // 0x0208(0x0018)()
	struct FSlateChildSize                        K2Node_MakeStruct_SlateChildSize_1;                // 0x0220(0x0008)(NoDestructor)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_4;            // 0x0228(0x0040)(HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0268(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31C6[0x4];                                     // 0x026C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UTextBlock*                             K2Node_Select_Default;                             // 0x0270(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_GetText_ReturnValue_1;                    // 0x0278(0x0018)()
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0290(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_31C7[0x7];                                     // 0x0291(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_5;            // 0x0298(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x02D8(0x0010)(ReferenceParm)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x02E8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31C8[0x4];                                     // 0x02EC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x02F0(0x0018)()
};
static_assert(alignof(CreditListItem_C_Refresh) == 0x000008, "Wrong alignment on CreditListItem_C_Refresh");
static_assert(sizeof(CreditListItem_C_Refresh) == 0x000308, "Wrong size on CreditListItem_C_Refresh");
static_assert(offsetof(CreditListItem_C_Refresh, New_Columns) == 0x000000, "Member 'CreditListItem_C_Refresh::New_Columns' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_SlateChildSize) == 0x000010, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_SlateChildSize' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, Temp_bool_Variable) == 0x000018, "Member 'CreditListItem_C_Refresh::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, Temp_int_Array_Index_Variable) == 0x00001C, "Member 'CreditListItem_C_Refresh::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, Temp_int_Loop_Counter_Variable) == 0x000020, "Member 'CreditListItem_C_Refresh::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Add_IntInt_ReturnValue) == 0x000024, "Member 'CreditListItem_C_Refresh::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, Temp_int_Array_Index_Variable_1) == 0x000028, "Member 'CreditListItem_C_Refresh::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x00002C, "Member 'CreditListItem_C_Refresh::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Array_Get_Item) == 0x000030, "Member 'CreditListItem_C_Refresh::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Conv_StringToText_ReturnValue) == 0x000040, "Member 'CreditListItem_C_Refresh::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Array_Get_Item_1) == 0x000058, "Member 'CreditListItem_C_Refresh::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData) == 0x000068, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Conv_StringToText_ReturnValue_1) == 0x0000A8, "Member 'CreditListItem_C_Refresh::CallFunc_Conv_StringToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Array_Length_ReturnValue) == 0x0000C0, "Member 'CreditListItem_C_Refresh::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000C8, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Array_Length_ReturnValue_1) == 0x000108, "Member 'CreditListItem_C_Refresh::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Array_Length_ReturnValue_2) == 0x00010C, "Member 'CreditListItem_C_Refresh::CallFunc_Array_Length_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Less_IntInt_ReturnValue) == 0x000110, "Member 'CreditListItem_C_Refresh::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Greater_IntInt_ReturnValue) == 0x000111, "Member 'CreditListItem_C_Refresh::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_SwitchInteger_CmpSuccess) == 0x000112, "Member 'CreditListItem_C_Refresh::K2Node_SwitchInteger_CmpSuccess' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_SlotAsHorizontalBoxSlot_ReturnValue) == 0x000118, "Member 'CreditListItem_C_Refresh::CallFunc_SlotAsHorizontalBoxSlot_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_1) == 0x000120, "Member 'CreditListItem_C_Refresh::CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_MakeLiteralText_ReturnValue) == 0x000128, "Member 'CreditListItem_C_Refresh::CallFunc_MakeLiteralText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_GetText_ReturnValue) == 0x000140, "Member 'CreditListItem_C_Refresh::CallFunc_GetText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData_2) == 0x000158, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData_3) == 0x000198, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData_3' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeArray_Array) == 0x0001D8, "Member 'CreditListItem_C_Refresh::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_2) == 0x0001E8, "Member 'CreditListItem_C_Refresh::CallFunc_SlotAsHorizontalBoxSlot_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Format_ReturnValue) == 0x0001F0, "Member 'CreditListItem_C_Refresh::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_MakeLiteralText_ReturnValue_1) == 0x000208, "Member 'CreditListItem_C_Refresh::CallFunc_MakeLiteralText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_SlateChildSize_1) == 0x000220, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_SlateChildSize_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData_4) == 0x000228, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData_4' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, Temp_int_Loop_Counter_Variable_1) == 0x000268, "Member 'CreditListItem_C_Refresh::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_Select_Default) == 0x000270, "Member 'CreditListItem_C_Refresh::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_GetText_ReturnValue_1) == 0x000278, "Member 'CreditListItem_C_Refresh::CallFunc_GetText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Less_IntInt_ReturnValue_1) == 0x000290, "Member 'CreditListItem_C_Refresh::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeStruct_FormatArgumentData_5) == 0x000298, "Member 'CreditListItem_C_Refresh::K2Node_MakeStruct_FormatArgumentData_5' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, K2Node_MakeArray_Array_1) == 0x0002D8, "Member 'CreditListItem_C_Refresh::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Add_IntInt_ReturnValue_1) == 0x0002E8, "Member 'CreditListItem_C_Refresh::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditListItem_C_Refresh, CallFunc_Format_ReturnValue_1) == 0x0002F0, "Member 'CreditListItem_C_Refresh::CallFunc_Format_ReturnValue_1' has a wrong offset!");

}
