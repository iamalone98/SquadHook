#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ParseKeybindItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SlateCore_structs.hpp"
#include "InputCore_structs.hpp"


namespace SDK::Params
{

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.ExecuteUbergraph_W_ParseKeybindItem
// 0x00B0 (0x00B0 - 0x0000)
struct W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Conv_TextToString_ReturnValue;            // 0x0040(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43B5[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Parse_Keybind_Short_Name;                 // 0x0058(0x0018)()
	class UBorderSlot*                            CallFunc_SlotAsBorderSlot_ReturnValue;             // 0x0070(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Conv_TextToString_ReturnValue_1;          // 0x0078(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Parse_Keybind_Short_Name_1;               // 0x0088(0x0018)()
	class USizeBoxSlot*                           K2Node_DynamicCast_AsSize_Box_Slot;                // 0x00A0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem) == 0x000008, "Wrong alignment on W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem");
static_assert(sizeof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem) == 0x0000B0, "Wrong size on W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, EntryPoint) == 0x000000, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, K2Node_Event_MyGeometry) == 0x000004, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, CallFunc_Conv_TextToString_ReturnValue) == 0x000040, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::CallFunc_Conv_TextToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, K2Node_Event_IsDesignTime) == 0x000050, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, CallFunc_Parse_Keybind_Short_Name) == 0x000058, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::CallFunc_Parse_Keybind_Short_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, CallFunc_SlotAsBorderSlot_ReturnValue) == 0x000070, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::CallFunc_SlotAsBorderSlot_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, CallFunc_Conv_TextToString_ReturnValue_1) == 0x000078, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::CallFunc_Conv_TextToString_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, CallFunc_Parse_Keybind_Short_Name_1) == 0x000088, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::CallFunc_Parse_Keybind_Short_Name_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, K2Node_DynamicCast_AsSize_Box_Slot) == 0x0000A0, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::K2Node_DynamicCast_AsSize_Box_Slot' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem, K2Node_DynamicCast_bSuccess) == 0x0000A8, "Member 'W_ParseKeybindItem_C_ExecuteUbergraph_W_ParseKeybindItem::K2Node_DynamicCast_bSuccess' has a wrong offset!");

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct W_ParseKeybindItem_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_ParseKeybindItem_C_PreConstruct) == 0x000001, "Wrong alignment on W_ParseKeybindItem_C_PreConstruct");
static_assert(sizeof(W_ParseKeybindItem_C_PreConstruct) == 0x000001, "Wrong size on W_ParseKeybindItem_C_PreConstruct");
static_assert(offsetof(W_ParseKeybindItem_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'W_ParseKeybindItem_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_ParseKeybindItem_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ParseKeybindItem_C_Tick) == 0x000004, "Wrong alignment on W_ParseKeybindItem_C_Tick");
static_assert(sizeof(W_ParseKeybindItem_C_Tick) == 0x00003C, "Wrong size on W_ParseKeybindItem_C_Tick");
static_assert(offsetof(W_ParseKeybindItem_C_Tick, MyGeometry) == 0x000000, "Member 'W_ParseKeybindItem_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Tick, InDeltaTime) == 0x000038, "Member 'W_ParseKeybindItem_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Parse Keybind
// 0x02A0 (0x02A0 - 0x0000)
struct W_ParseKeybindItem_C_Parse_Keybind final
{
public:
	class FString                                 InString;                                          // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, HasGetValueTypeHash)
	class FText                                   Short_Name;                                        // 0x0010(0x0018)(Parm, OutParm)
	TArray<class FName>                           L_Axis_List;                                       // 0x0028(0x0010)(Edit, BlueprintVisible)
	class FText                                   L_Axis;                                            // 0x0038(0x0018)(Edit, BlueprintVisible)
	bool                                          Temp_bool_Variable;                                // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43B6[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_Conv_StringToName_ReturnValue;            // 0x0054(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FInputAxisKeyMapping>           CallFunc_GetKeysMapedToAxis_Keys;                  // 0x0060(0x0010)(ReferenceParm)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0070(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0074(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43B7[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FInputAxisKeyMapping>           CallFunc_GetKeysMapedToAxis_Keys_1;                // 0x0080(0x0010)(ReferenceParm)
	class FName                                   CallFunc_GetActionKeyName_Name;                    // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_43B8[0x4];                                     // 0x009C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Get_Short_Name_Short_Name;                // 0x00A0(0x0018)()
	class FString                                 CallFunc_Conv_NameToString_ReturnValue;            // 0x00B8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_Contains_ReturnValue;                     // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43B9[0x3];                                     // 0x00C9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable;                     // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x00D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_43BA[0x4];                                     // 0x00D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FInputAxisKeyMapping                   CallFunc_Array_Get_Item;                           // 0x00D8(0x0028)()
	class FName                                   CallFunc_BreakInputAxisKeyMapping_ActionName;      // 0x0100(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FKey                                   CallFunc_BreakInputAxisKeyMapping_Key;             // 0x0108(0x0018)(HasGetValueTypeHash)
	float                                         CallFunc_BreakInputAxisKeyMapping_Scale;           // 0x0120(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetKeyName_OutName;                       // 0x0124(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Key_IsKeyboardKey_ReturnValue;            // 0x012C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43BB[0x3];                                     // 0x012D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0130(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0134(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43BC[0x3];                                     // 0x0135(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0138(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_2;                   // 0x013C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FInputAxisKeyMapping                   CallFunc_Array_Get_Item_1;                         // 0x0140(0x0028)()
	int32                                         CallFunc_Array_AddUnique_ReturnValue;              // 0x0168(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_BreakInputAxisKeyMapping_ActionName_1;    // 0x016C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_43BD[0x4];                                     // 0x0174(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   CallFunc_BreakInputAxisKeyMapping_Key_1;           // 0x0178(0x0018)(HasGetValueTypeHash)
	float                                         CallFunc_BreakInputAxisKeyMapping_Scale_1;         // 0x0190(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_GetKeyName_OutName_1;                     // 0x0194(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Key_IsKeyboardKey_ReturnValue_1;          // 0x019C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43BE[0x3];                                     // 0x019D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x01A0(0x0040)(HasGetValueTypeHash)
	bool                                          CallFunc_TextIsEmpty_ReturnValue;                  // 0x01E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43BF[0x3];                                     // 0x01E1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CallFunc_Array_Get_Item_2;                         // 0x01E4(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_2;               // 0x01EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Get_Short_Name_Short_Name_1;              // 0x01F0(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0208(0x0040)(HasGetValueTypeHash)
	int32                                         CallFunc_Array_AddUnique_ReturnValue_1;            // 0x0248(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_43C0[0x4];                                     // 0x024C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0250(0x0010)(ReferenceParm)
	int32                                         Temp_int_Loop_Counter_Variable_2;                  // 0x0260(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_43C1[0x4];                                     // 0x0264(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0268(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0280(0x0018)()
	bool                                          CallFunc_Less_IntInt_ReturnValue_2;                // 0x0298(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_43C2[0x3];                                     // 0x0299(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_2;                 // 0x029C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ParseKeybindItem_C_Parse_Keybind) == 0x000008, "Wrong alignment on W_ParseKeybindItem_C_Parse_Keybind");
static_assert(sizeof(W_ParseKeybindItem_C_Parse_Keybind) == 0x0002A0, "Wrong size on W_ParseKeybindItem_C_Parse_Keybind");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, InString) == 0x000000, "Member 'W_ParseKeybindItem_C_Parse_Keybind::InString' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Short_Name) == 0x000010, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Short_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, L_Axis_List) == 0x000028, "Member 'W_ParseKeybindItem_C_Parse_Keybind::L_Axis_List' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, L_Axis) == 0x000038, "Member 'W_ParseKeybindItem_C_Parse_Keybind::L_Axis' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_bool_Variable) == 0x000050, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Conv_StringToName_ReturnValue) == 0x000054, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Conv_StringToName_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Loop_Counter_Variable) == 0x00005C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_GetKeysMapedToAxis_Keys) == 0x000060, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_GetKeysMapedToAxis_Keys' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Add_IntInt_ReturnValue) == 0x000070, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Length_ReturnValue) == 0x000074, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Less_IntInt_ReturnValue) == 0x000078, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_GetKeysMapedToAxis_Keys_1) == 0x000080, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_GetKeysMapedToAxis_Keys_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_GetActionKeyName_Name) == 0x000090, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_GetActionKeyName_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Length_ReturnValue_1) == 0x000098, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Get_Short_Name_Short_Name) == 0x0000A0, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Get_Short_Name_Short_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Conv_NameToString_ReturnValue) == 0x0000B8, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Conv_NameToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Contains_ReturnValue) == 0x0000C8, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Contains_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Array_Index_Variable) == 0x0000CC, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Array_Index_Variable_1) == 0x0000D0, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Get_Item) == 0x0000D8, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_ActionName) == 0x000100, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_ActionName' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_Key) == 0x000108, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_Key' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_Scale) == 0x000120, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_Scale' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_GetKeyName_OutName) == 0x000124, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_GetKeyName_OutName' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Key_IsKeyboardKey_ReturnValue) == 0x00012C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Key_IsKeyboardKey_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Loop_Counter_Variable_1) == 0x000130, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Less_IntInt_ReturnValue_1) == 0x000134, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Add_IntInt_ReturnValue_1) == 0x000138, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Array_Index_Variable_2) == 0x00013C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Array_Index_Variable_2' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Get_Item_1) == 0x000140, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_AddUnique_ReturnValue) == 0x000168, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_AddUnique_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_ActionName_1) == 0x00016C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_ActionName_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_Key_1) == 0x000178, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_Key_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_BreakInputAxisKeyMapping_Scale_1) == 0x000190, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_BreakInputAxisKeyMapping_Scale_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_GetKeyName_OutName_1) == 0x000194, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_GetKeyName_OutName_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Key_IsKeyboardKey_ReturnValue_1) == 0x00019C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Key_IsKeyboardKey_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, K2Node_MakeStruct_FormatArgumentData) == 0x0001A0, "Member 'W_ParseKeybindItem_C_Parse_Keybind::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_TextIsEmpty_ReturnValue) == 0x0001E0, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_TextIsEmpty_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Get_Item_2) == 0x0001E4, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Get_Item_2' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_Length_ReturnValue_2) == 0x0001EC, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_Length_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Get_Short_Name_Short_Name_1) == 0x0001F0, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Get_Short_Name_Short_Name_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, K2Node_MakeStruct_FormatArgumentData_1) == 0x000208, "Member 'W_ParseKeybindItem_C_Parse_Keybind::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Array_AddUnique_ReturnValue_1) == 0x000248, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Array_AddUnique_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, K2Node_MakeArray_Array) == 0x000250, "Member 'W_ParseKeybindItem_C_Parse_Keybind::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, Temp_int_Loop_Counter_Variable_2) == 0x000260, "Member 'W_ParseKeybindItem_C_Parse_Keybind::Temp_int_Loop_Counter_Variable_2' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Format_ReturnValue) == 0x000268, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, K2Node_Select_Default) == 0x000280, "Member 'W_ParseKeybindItem_C_Parse_Keybind::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Less_IntInt_ReturnValue_2) == 0x000298, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Less_IntInt_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Parse_Keybind, CallFunc_Add_IntInt_ReturnValue_2) == 0x00029C, "Member 'W_ParseKeybindItem_C_Parse_Keybind::CallFunc_Add_IntInt_ReturnValue_2' has a wrong offset!");

// Function W_ParseKeybindItem.W_ParseKeybindItem_C.Get Short Name
// 0x0040 (0x0040 - 0x0000)
struct W_ParseKeybindItem_C_Get_Short_Name final
{
public:
	class FName                                   Action_Name;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   Short_Name;                                        // 0x0008(0x0018)(Parm, OutParm)
	class FText                                   CallFunc_Conv_NameToText_ReturnValue;              // 0x0020(0x0018)()
	bool                                          K2Node_SwitchName_CmpSuccess;                      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_NameName_ReturnValue;          // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_NameName_ReturnValue_1;        // 0x003A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_NameName_ReturnValue_2;        // 0x003B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_ParseKeybindItem_C_Get_Short_Name) == 0x000008, "Wrong alignment on W_ParseKeybindItem_C_Get_Short_Name");
static_assert(sizeof(W_ParseKeybindItem_C_Get_Short_Name) == 0x000040, "Wrong size on W_ParseKeybindItem_C_Get_Short_Name");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, Action_Name) == 0x000000, "Member 'W_ParseKeybindItem_C_Get_Short_Name::Action_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, Short_Name) == 0x000008, "Member 'W_ParseKeybindItem_C_Get_Short_Name::Short_Name' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, CallFunc_Conv_NameToText_ReturnValue) == 0x000020, "Member 'W_ParseKeybindItem_C_Get_Short_Name::CallFunc_Conv_NameToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, K2Node_SwitchName_CmpSuccess) == 0x000038, "Member 'W_ParseKeybindItem_C_Get_Short_Name::K2Node_SwitchName_CmpSuccess' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, CallFunc_EqualEqual_NameName_ReturnValue) == 0x000039, "Member 'W_ParseKeybindItem_C_Get_Short_Name::CallFunc_EqualEqual_NameName_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, CallFunc_EqualEqual_NameName_ReturnValue_1) == 0x00003A, "Member 'W_ParseKeybindItem_C_Get_Short_Name::CallFunc_EqualEqual_NameName_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_ParseKeybindItem_C_Get_Short_Name, CallFunc_EqualEqual_NameName_ReturnValue_2) == 0x00003B, "Member 'W_ParseKeybindItem_C_Get_Short_Name::CallFunc_EqualEqual_NameName_ReturnValue_2' has a wrong offset!");

}
