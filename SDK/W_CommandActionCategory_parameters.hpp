#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CommandActionCategory

#include "Basic.hpp"

#include "UMG_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_CommandActionCategory.W_CommandActionCategory_C.ExecuteUbergraph_W_CommandActionCategory
// 0x00E0 (0x00E0 - 0x0000)
struct W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40BB[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameState*                           CallFunc_TryGetGameState_OutGameState;             // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetGameState_ReturnValue;              // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40BC[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Variable;                                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Temp_object_Variable;                              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Temp_object_Variable_1;                            // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40BD[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandActionItem_C*                 CallFunc_Create_ReturnValue;                       // 0x0048(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40BE[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TSubclassOf<class USQGridData_CommandOption>> CallFunc_GetCommandActionsById_ReturnValue;        // 0x0068(0x0010)(ReferenceParm)
	class UVerticalBoxSlot*                       CallFunc_AddChildToVerticalBox_ReturnValue;        // 0x0078(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 CallFunc_Array_Get_Item;                           // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x008C(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40BF[0x3];                                     // 0x00C9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Conv_ByteToInt_ReturnValue;               // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x00D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Conv_ByteToInt_ReturnValue_1;             // 0x00D4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             K2Node_Select_Default;                             // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory) == 0x000008, "Wrong alignment on W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory");
static_assert(sizeof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory) == 0x0000E0, "Wrong size on W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, EntryPoint) == 0x000000, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_TryGetGameState_OutGameState) == 0x000008, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_TryGetGameState_OutGameState' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_TryGetGameState_ReturnValue) == 0x000010, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_TryGetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, Temp_int_Variable) == 0x000014, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, Temp_object_Variable) == 0x000018, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::Temp_object_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, Temp_object_Variable_1) == 0x000020, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::Temp_object_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, Temp_int_Array_Index_Variable) == 0x000028, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, Temp_int_Loop_Counter_Variable) == 0x00002C, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Add_IntInt_ReturnValue) == 0x000030, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_GetOwningPlayer_ReturnValue) == 0x000038, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000040, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Create_ReturnValue) == 0x000048, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000050, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000058, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, K2Node_DynamicCast_bSuccess) == 0x000060, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_GetCommandActionsById_ReturnValue) == 0x000068, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_GetCommandActionsById_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_AddChildToVerticalBox_ReturnValue) == 0x000078, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_AddChildToVerticalBox_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Array_Get_Item) == 0x000080, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Array_Length_ReturnValue) == 0x000088, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, K2Node_Event_MyGeometry) == 0x00008C, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, K2Node_Event_InDeltaTime) == 0x0000C4, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Less_IntInt_ReturnValue) == 0x0000C8, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Conv_ByteToInt_ReturnValue) == 0x0000CC, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Conv_ByteToInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Array_Add_ReturnValue) == 0x0000D0, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, CallFunc_Conv_ByteToInt_ReturnValue_1) == 0x0000D4, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::CallFunc_Conv_ByteToInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory, K2Node_Select_Default) == 0x0000D8, "Member 'W_CommandActionCategory_C_ExecuteUbergraph_W_CommandActionCategory::K2Node_Select_Default' has a wrong offset!");

// Function W_CommandActionCategory.W_CommandActionCategory_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_CommandActionCategory_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandActionCategory_C_Tick) == 0x000004, "Wrong alignment on W_CommandActionCategory_C_Tick");
static_assert(sizeof(W_CommandActionCategory_C_Tick) == 0x00003C, "Wrong size on W_CommandActionCategory_C_Tick");
static_assert(offsetof(W_CommandActionCategory_C_Tick, MyGeometry) == 0x000000, "Member 'W_CommandActionCategory_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Tick, InDeltaTime) == 0x000038, "Member 'W_CommandActionCategory_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_CommandActionCategory.W_CommandActionCategory_C.Update Category
// 0x01C8 (0x01C8 - 0x0000)
struct W_CommandActionCategory_C_Update_Category final
{
public:
	float                                         Remaining_Time;                                    // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          L_Locked;                                          // 0x0004(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0006(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0007(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	bool                                          Temp_bool_Variable_1;                              // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C0[0x3];                                     // 0x0021(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Temp_float_Variable;                               // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Temp_float_Variable_1;                             // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_2;                              // 0x002C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C1[0x3];                                     // 0x002D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Temp_float_Variable_2;                             // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Temp_float_Variable_3;                             // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue; // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Select_Default;                             // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           K2Node_MakeStruct_LinearColor;                     // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateColor                            K2Node_MakeStruct_SlateColor;                      // 0x0050(0x0028)()
	float                                         K2Node_Select_Default_1;                           // 0x0078(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_3;                              // 0x007C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C2[0x3];                                     // 0x007D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           K2Node_MakeStruct_LinearColor_1;                   // 0x0080(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default_2;                           // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40C3[0x7];                                     // 0x0091(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimespan                              CallFunc_FromSeconds_ReturnValue;                  // 0x0098(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Days;                       // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Hours;                      // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Minutes;                    // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Seconds;                    // 0x00AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Milliseconds;               // 0x00B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40C4[0x4];                                     // 0x00B4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x00B8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x00D0(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_1;             // 0x0110(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0128(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0168(0x0010)(ReferenceParm)
	bool                                          CallFunc_Greater_FloatFloat_ReturnValue;           // 0x0178(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C5[0x7];                                     // 0x0179(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0180(0x0018)()
	float                                         CallFunc_CalculateCategoryPercentRemainingTime_ReturnValue; // 0x0198(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_FloatFloat_ReturnValue_1;         // 0x019C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C6[0x3];                                     // 0x019D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_Select_Default_3;                           // 0x01A0(0x0018)()
	struct FLinearColor                           K2Node_MakeStruct_LinearColor_2;                   // 0x01B8(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CommandActionCategory_C_Update_Category) == 0x000008, "Wrong alignment on W_CommandActionCategory_C_Update_Category");
static_assert(sizeof(W_CommandActionCategory_C_Update_Category) == 0x0001C8, "Wrong size on W_CommandActionCategory_C_Update_Category");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Remaining_Time) == 0x000000, "Member 'W_CommandActionCategory_C_Update_Category::Remaining_Time' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, L_Locked) == 0x000004, "Member 'W_CommandActionCategory_C_Update_Category::L_Locked' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_byte_Variable) == 0x000005, "Member 'W_CommandActionCategory_C_Update_Category::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_byte_Variable_1) == 0x000006, "Member 'W_CommandActionCategory_C_Update_Category::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_bool_Variable) == 0x000007, "Member 'W_CommandActionCategory_C_Update_Category::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_text_Variable) == 0x000008, "Member 'W_CommandActionCategory_C_Update_Category::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_bool_Variable_1) == 0x000020, "Member 'W_CommandActionCategory_C_Update_Category::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_float_Variable) == 0x000024, "Member 'W_CommandActionCategory_C_Update_Category::Temp_float_Variable' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_float_Variable_1) == 0x000028, "Member 'W_CommandActionCategory_C_Update_Category::Temp_float_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_bool_Variable_2) == 0x00002C, "Member 'W_CommandActionCategory_C_Update_Category::Temp_bool_Variable_2' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_float_Variable_2) == 0x000030, "Member 'W_CommandActionCategory_C_Update_Category::Temp_float_Variable_2' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_float_Variable_3) == 0x000034, "Member 'W_CommandActionCategory_C_Update_Category::Temp_float_Variable_3' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue) == 0x000038, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_Select_Default) == 0x00003C, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_LinearColor) == 0x000040, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_LinearColor' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_SlateColor) == 0x000050, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_SlateColor' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_Select_Default_1) == 0x000078, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, Temp_bool_Variable_3) == 0x00007C, "Member 'W_CommandActionCategory_C_Update_Category::Temp_bool_Variable_3' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_LinearColor_1) == 0x000080, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_LinearColor_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_Select_Default_2) == 0x000090, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_Select_Default_2' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_FromSeconds_ReturnValue) == 0x000098, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_FromSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_BreakTimespan_Days) == 0x0000A0, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_BreakTimespan_Days' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_BreakTimespan_Hours) == 0x0000A4, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_BreakTimespan_Hours' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_BreakTimespan_Minutes) == 0x0000A8, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_BreakTimespan_Minutes' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_BreakTimespan_Seconds) == 0x0000AC, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_BreakTimespan_Seconds' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_BreakTimespan_Milliseconds) == 0x0000B0, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_BreakTimespan_Milliseconds' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_Conv_IntToText_ReturnValue) == 0x0000B8, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_FormatArgumentData) == 0x0000D0, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_Conv_IntToText_ReturnValue_1) == 0x000110, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_Conv_IntToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_FormatArgumentData_1) == 0x000128, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeArray_Array) == 0x000168, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_Greater_FloatFloat_ReturnValue) == 0x000178, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_Greater_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_Format_ReturnValue) == 0x000180, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_CalculateCategoryPercentRemainingTime_ReturnValue) == 0x000198, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_CalculateCategoryPercentRemainingTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, CallFunc_Greater_FloatFloat_ReturnValue_1) == 0x00019C, "Member 'W_CommandActionCategory_C_Update_Category::CallFunc_Greater_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_Select_Default_3) == 0x0001A0, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_Select_Default_3' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Update_Category, K2Node_MakeStruct_LinearColor_2) == 0x0001B8, "Member 'W_CommandActionCategory_C_Update_Category::K2Node_MakeStruct_LinearColor_2' has a wrong offset!");

// Function W_CommandActionCategory.W_CommandActionCategory_C.Check Interaction
// 0x0018 (0x0018 - 0x0000)
struct W_CommandActionCategory_C_Check_Interaction final
{
public:
	bool                                          Locked;                                            // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40C7[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        CallFunc_GetCurrentRole_ReturnValue;               // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsSquadLeader_ReturnValue;                // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GetActionsEnabled_ReturnValue;            // 0x0013(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0015(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue_1;                // 0x0016(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CommandActionCategory_C_Check_Interaction) == 0x000008, "Wrong alignment on W_CommandActionCategory_C_Check_Interaction");
static_assert(sizeof(W_CommandActionCategory_C_Check_Interaction) == 0x000018, "Wrong size on W_CommandActionCategory_C_Check_Interaction");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, Locked) == 0x000000, "Member 'W_CommandActionCategory_C_Check_Interaction::Locked' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_GetCurrentRole_ReturnValue) == 0x000008, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_GetCurrentRole_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_IsCommander_ReturnValue) == 0x000010, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_IsCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_IsSquadLeader_ReturnValue) == 0x000012, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_IsSquadLeader_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_GetActionsEnabled_ReturnValue) == 0x000013, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_GetActionsEnabled_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_BooleanAND_ReturnValue) == 0x000014, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_Not_PreBool_ReturnValue) == 0x000015, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CommandActionCategory_C_Check_Interaction, CallFunc_Not_PreBool_ReturnValue_1) == 0x000016, "Member 'W_CommandActionCategory_C_Check_Interaction::CallFunc_Not_PreBool_ReturnValue_1' has a wrong offset!");

}

