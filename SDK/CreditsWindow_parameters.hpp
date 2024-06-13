#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: CreditsWindow

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function CreditsWindow.CreditsWindow_C.ExecuteUbergraph_CreditsWindow
// 0x0168 (0x0168 - 0x0000)
struct CreditsWindow_C_ExecuteUbergraph_CreditsWindow final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry_1;                         // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetScrollOffset_ReturnValue;              // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FPointerEvent                          K2Node_Event_MouseEvent_1;                         // 0x0048(0x0070)(ConstParm)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x00BC(0x0038)(IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A2[0x4];                                     // 0x00F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPointerEvent                          K2Node_Event_MouseEvent;                           // 0x00F8(0x0070)(ConstParm)
};
static_assert(alignof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow) == 0x000008, "Wrong alignment on CreditsWindow_C_ExecuteUbergraph_CreditsWindow");
static_assert(sizeof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow) == 0x000168, "Wrong size on CreditsWindow_C_ExecuteUbergraph_CreditsWindow");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, EntryPoint) == 0x000000, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::EntryPoint' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, K2Node_Event_MyGeometry_1) == 0x000004, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::K2Node_Event_MyGeometry_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000040, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, CallFunc_GetScrollOffset_ReturnValue) == 0x000044, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::CallFunc_GetScrollOffset_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, K2Node_Event_MouseEvent_1) == 0x000048, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::K2Node_Event_MouseEvent_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, CallFunc_Add_FloatFloat_ReturnValue) == 0x0000B8, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, K2Node_Event_MyGeometry) == 0x0000BC, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_ExecuteUbergraph_CreditsWindow, K2Node_Event_MouseEvent) == 0x0000F8, "Member 'CreditsWindow_C_ExecuteUbergraph_CreditsWindow::K2Node_Event_MouseEvent' has a wrong offset!");

// Function CreditsWindow.CreditsWindow_C.OnMouseEnter
// 0x00A8 (0x00A8 - 0x0000)
struct CreditsWindow_C_OnMouseEnter final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
};
static_assert(alignof(CreditsWindow_C_OnMouseEnter) == 0x000008, "Wrong alignment on CreditsWindow_C_OnMouseEnter");
static_assert(sizeof(CreditsWindow_C_OnMouseEnter) == 0x0000A8, "Wrong size on CreditsWindow_C_OnMouseEnter");
static_assert(offsetof(CreditsWindow_C_OnMouseEnter, MyGeometry) == 0x000000, "Member 'CreditsWindow_C_OnMouseEnter::MyGeometry' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_OnMouseEnter, MouseEvent) == 0x000038, "Member 'CreditsWindow_C_OnMouseEnter::MouseEvent' has a wrong offset!");

// Function CreditsWindow.CreditsWindow_C.OnMouseLeave
// 0x0070 (0x0070 - 0x0000)
struct CreditsWindow_C_OnMouseLeave final
{
public:
	struct FPointerEvent                          MouseEvent;                                        // 0x0000(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
};
static_assert(alignof(CreditsWindow_C_OnMouseLeave) == 0x000008, "Wrong alignment on CreditsWindow_C_OnMouseLeave");
static_assert(sizeof(CreditsWindow_C_OnMouseLeave) == 0x000070, "Wrong size on CreditsWindow_C_OnMouseLeave");
static_assert(offsetof(CreditsWindow_C_OnMouseLeave, MouseEvent) == 0x000000, "Member 'CreditsWindow_C_OnMouseLeave::MouseEvent' has a wrong offset!");

// Function CreditsWindow.CreditsWindow_C.Tick
// 0x003C (0x003C - 0x0000)
struct CreditsWindow_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(CreditsWindow_C_Tick) == 0x000004, "Wrong alignment on CreditsWindow_C_Tick");
static_assert(sizeof(CreditsWindow_C_Tick) == 0x00003C, "Wrong size on CreditsWindow_C_Tick");
static_assert(offsetof(CreditsWindow_C_Tick, MyGeometry) == 0x000000, "Member 'CreditsWindow_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_Tick, InDeltaTime) == 0x000038, "Member 'CreditsWindow_C_Tick::InDeltaTime' has a wrong offset!");

// Function CreditsWindow.CreditsWindow_C.LoadCredits
// 0x0408 (0x0408 - 0x0000)
struct CreditsWindow_C_LoadCredits final
{
public:
	TArray<class FString>                         New_Strings;                                       // 0x0000(0x0010)(Edit, BlueprintVisible)
	class UCreditListItem_Header_C*               Last_Header;                                       // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQCreditsList                         Current_Credit;                                    // 0x0018(0x0028)(Edit, BlueprintVisible)
	int32                                         String_ID;                                         // 0x0040(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Do_4_Columns;                                      // 0x0044(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A3[0x3];                                     // 0x0045(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UCreditListItem_C*                      Last_Text_Item;                                    // 0x0048(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class FString>                         Local_Strings;                                     // 0x0050(0x0010)(Edit, BlueprintVisible)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x006C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A4[0x3];                                     // 0x006D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetText_ReturnValue;                      // 0x0070(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0088(0x0040)(HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_StrStr_ReturnValue;            // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A5[0x7];                                     // 0x00C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x00D0(0x0018)()
	TArray<class FString>                         K2Node_MakeArray_Array;                            // 0x00E8(0x0010)(ReferenceParm)
	class FString                                 CallFunc_Array_Get_Item;                           // 0x00F8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Concat_StrStr_ReturnValue;                // 0x0108(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_Array_IsValidIndex_ReturnValue;           // 0x0118(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A6[0x7];                                     // 0x0119(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Concat_StrStr_ReturnValue_1;              // 0x0120(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0130(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCreditListItem_4Columns_C*             CallFunc_Create_ReturnValue;                       // 0x0138(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue;                     // 0x0140(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0148(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x014C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A7[0x3];                                     // 0x014D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0150(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_35A8[0x4];                                     // 0x0154(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_MakeLiteralText_ReturnValue;              // 0x0158(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0170(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x01B0(0x0010)(ReferenceParm)
	class FText                                   CallFunc_GetText_ReturnValue_1;                    // 0x01C0(0x0018)()
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x01D8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x01F0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_MakeLiteralText_ReturnValue_1;            // 0x0230(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_3;            // 0x0248(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_GetText_ReturnValue_2;                    // 0x0288(0x0018)()
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_2;                          // 0x02A0(0x0010)(ReferenceParm)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_4;            // 0x02B0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x02F0(0x0018)()
	class FText                                   CallFunc_MakeLiteralText_ReturnValue_2;            // 0x0308(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_5;            // 0x0320(0x0040)(HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0360(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_3;                          // 0x0368(0x0010)(ReferenceParm)
	class UCreditListItem_C*                      CallFunc_Create_ReturnValue_1;                     // 0x0378(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Format_ReturnValue_2;                     // 0x0380(0x0018)()
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0398(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0399(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A9[0x6];                                     // 0x039A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_2;            // 0x03A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue_1;                   // 0x03A8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCreditListItem_Header_C*               CallFunc_Create_ReturnValue_2;                     // 0x03B0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue_2;                   // 0x03B8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FSQCreditsList>                 CallFunc_LoadCredits_OutCreditsList;               // 0x03C0(0x0010)(ReferenceParm)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x03D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_35AA[0x4];                                     // 0x03D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQCreditsList                         CallFunc_Array_Get_Item_1;                         // 0x03D8(0x0028)()
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0400(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_SwitchEnum_CmpSuccess;                      // 0x0401(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(CreditsWindow_C_LoadCredits) == 0x000008, "Wrong alignment on CreditsWindow_C_LoadCredits");
static_assert(sizeof(CreditsWindow_C_LoadCredits) == 0x000408, "Wrong size on CreditsWindow_C_LoadCredits");
static_assert(offsetof(CreditsWindow_C_LoadCredits, New_Strings) == 0x000000, "Member 'CreditsWindow_C_LoadCredits::New_Strings' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Last_Header) == 0x000010, "Member 'CreditsWindow_C_LoadCredits::Last_Header' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Current_Credit) == 0x000018, "Member 'CreditsWindow_C_LoadCredits::Current_Credit' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, String_ID) == 0x000040, "Member 'CreditsWindow_C_LoadCredits::String_ID' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Do_4_Columns) == 0x000044, "Member 'CreditsWindow_C_LoadCredits::Do_4_Columns' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Last_Text_Item) == 0x000048, "Member 'CreditsWindow_C_LoadCredits::Last_Text_Item' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Local_Strings) == 0x000050, "Member 'CreditsWindow_C_LoadCredits::Local_Strings' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Temp_int_Loop_Counter_Variable) == 0x000060, "Member 'CreditsWindow_C_LoadCredits::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Add_IntInt_ReturnValue) == 0x000064, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Temp_int_Array_Index_Variable) == 0x000068, "Member 'CreditsWindow_C_LoadCredits::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_IsValid_ReturnValue) == 0x00006C, "Member 'CreditsWindow_C_LoadCredits::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetText_ReturnValue) == 0x000070, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData) == 0x000088, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_EqualEqual_StrStr_ReturnValue) == 0x0000C8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_EqualEqual_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Conv_StringToText_ReturnValue) == 0x0000D0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeArray_Array) == 0x0000E8, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Array_Get_Item) == 0x0000F8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Concat_StrStr_ReturnValue) == 0x000108, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Concat_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Array_IsValidIndex_ReturnValue) == 0x000118, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Array_IsValidIndex_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Concat_StrStr_ReturnValue_1) == 0x000120, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Concat_StrStr_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetOwningPlayer_ReturnValue) == 0x000130, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Create_ReturnValue) == 0x000138, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_AddChild_ReturnValue) == 0x000140, "Member 'CreditsWindow_C_LoadCredits::CallFunc_AddChild_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, Temp_int_Variable) == 0x000148, "Member 'CreditsWindow_C_LoadCredits::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Less_IntInt_ReturnValue) == 0x00014C, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Add_IntInt_ReturnValue_1) == 0x000150, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_MakeLiteralText_ReturnValue) == 0x000158, "Member 'CreditsWindow_C_LoadCredits::CallFunc_MakeLiteralText_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData_1) == 0x000170, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeArray_Array_1) == 0x0001B0, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetText_ReturnValue_1) == 0x0001C0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Format_ReturnValue) == 0x0001D8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData_2) == 0x0001F0, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_MakeLiteralText_ReturnValue_1) == 0x000230, "Member 'CreditsWindow_C_LoadCredits::CallFunc_MakeLiteralText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData_3) == 0x000248, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData_3' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetText_ReturnValue_2) == 0x000288, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeArray_Array_2) == 0x0002A0, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeArray_Array_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData_4) == 0x0002B0, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData_4' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Format_ReturnValue_1) == 0x0002F0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Format_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_MakeLiteralText_ReturnValue_2) == 0x000308, "Member 'CreditsWindow_C_LoadCredits::CallFunc_MakeLiteralText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeStruct_FormatArgumentData_5) == 0x000320, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeStruct_FormatArgumentData_5' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000360, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_MakeArray_Array_3) == 0x000368, "Member 'CreditsWindow_C_LoadCredits::K2Node_MakeArray_Array_3' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Create_ReturnValue_1) == 0x000378, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Create_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Format_ReturnValue_2) == 0x000380, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Format_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_IsValid_ReturnValue_1) == 0x000398, "Member 'CreditsWindow_C_LoadCredits::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_IsValid_ReturnValue_2) == 0x000399, "Member 'CreditsWindow_C_LoadCredits::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_GetOwningPlayer_ReturnValue_2) == 0x0003A0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_GetOwningPlayer_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_AddChild_ReturnValue_1) == 0x0003A8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_AddChild_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Create_ReturnValue_2) == 0x0003B0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Create_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_AddChild_ReturnValue_2) == 0x0003B8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_AddChild_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_LoadCredits_OutCreditsList) == 0x0003C0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_LoadCredits_OutCreditsList' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Array_Length_ReturnValue) == 0x0003D0, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Array_Get_Item_1) == 0x0003D8, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, CallFunc_Less_IntInt_ReturnValue_1) == 0x000400, "Member 'CreditsWindow_C_LoadCredits::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_LoadCredits, K2Node_SwitchEnum_CmpSuccess) == 0x000401, "Member 'CreditsWindow_C_LoadCredits::K2Node_SwitchEnum_CmpSuccess' has a wrong offset!");

// Function CreditsWindow.CreditsWindow_C.CheckScrollToTop
// 0x0018 (0x0018 - 0x0000)
struct CreditsWindow_C_CheckScrollToTop final
{
public:
	class UScrollBox*                             ScrollBox;                                         // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         NewScrollOffset;                                   // 0x0008(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetScrollOffset_ReturnValue;              // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NearlyEqual_FloatFloat_ReturnValue;       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(CreditsWindow_C_CheckScrollToTop) == 0x000008, "Wrong alignment on CreditsWindow_C_CheckScrollToTop");
static_assert(sizeof(CreditsWindow_C_CheckScrollToTop) == 0x000018, "Wrong size on CreditsWindow_C_CheckScrollToTop");
static_assert(offsetof(CreditsWindow_C_CheckScrollToTop, ScrollBox) == 0x000000, "Member 'CreditsWindow_C_CheckScrollToTop::ScrollBox' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_CheckScrollToTop, NewScrollOffset) == 0x000008, "Member 'CreditsWindow_C_CheckScrollToTop::NewScrollOffset' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_CheckScrollToTop, CallFunc_GetScrollOffset_ReturnValue) == 0x00000C, "Member 'CreditsWindow_C_CheckScrollToTop::CallFunc_GetScrollOffset_ReturnValue' has a wrong offset!");
static_assert(offsetof(CreditsWindow_C_CheckScrollToTop, CallFunc_NearlyEqual_FloatFloat_ReturnValue) == 0x000010, "Member 'CreditsWindow_C_CheckScrollToTop::CallFunc_NearlyEqual_FloatFloat_ReturnValue' has a wrong offset!");

}
