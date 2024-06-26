#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CamControlButton

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SQFactionEntry_structs.hpp"
#include "Squad_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_CamControlButton.W_CamControlButton_C.Cam State Changed__DelegateSignature
// 0x0010 (0x0010 - 0x0000)
struct W_CamControlButton_C_Cam_State_Changed__DelegateSignature final
{
public:
	bool                                          Active;                                            // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A5[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_ControlledCamera_C*                 Cam;                                               // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CamControlButton_C_Cam_State_Changed__DelegateSignature) == 0x000008, "Wrong alignment on W_CamControlButton_C_Cam_State_Changed__DelegateSignature");
static_assert(sizeof(W_CamControlButton_C_Cam_State_Changed__DelegateSignature) == 0x000010, "Wrong size on W_CamControlButton_C_Cam_State_Changed__DelegateSignature");
static_assert(offsetof(W_CamControlButton_C_Cam_State_Changed__DelegateSignature, Active) == 0x000000, "Member 'W_CamControlButton_C_Cam_State_Changed__DelegateSignature::Active' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Cam_State_Changed__DelegateSignature, Cam) == 0x000008, "Member 'W_CamControlButton_C_Cam_State_Changed__DelegateSignature::Cam' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.ExecuteUbergraph_W_CamControlButton
// 0x0088 (0x0088 - 0x0000)
struct W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40A6[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameState*                           CallFunc_TryGetGameState_OutGameState;             // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetGameState_ReturnValue;              // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A7[0x1];                                     // 0x0013(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0014(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A8[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Can_Use_Actions_Valid;                    // 0x0069(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A9[0x6];                                     // 0x006A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Can_Use_Actions_Out_Reason;               // 0x0070(0x0018)()
};
static_assert(alignof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton) == 0x000008, "Wrong alignment on W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton");
static_assert(sizeof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton) == 0x000088, "Wrong size on W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, EntryPoint) == 0x000000, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_TryGetGameState_OutGameState) == 0x000008, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_TryGetGameState_OutGameState' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_TryGetGameState_ReturnValue) == 0x000010, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_TryGetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_IsValid_ReturnValue_1) == 0x000012, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, K2Node_Event_MyGeometry) == 0x000014, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, K2Node_Event_InDeltaTime) == 0x00004C, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, K2Node_Event_IsDesignTime) == 0x000050, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_GetOwningPlayer_ReturnValue) == 0x000058, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000060, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, K2Node_DynamicCast_bSuccess) == 0x000068, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_Can_Use_Actions_Valid) == 0x000069, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_Can_Use_Actions_Valid' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton, CallFunc_Can_Use_Actions_Out_Reason) == 0x000070, "Member 'W_CamControlButton_C_ExecuteUbergraph_W_CamControlButton::CallFunc_Can_Use_Actions_Out_Reason' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct W_CamControlButton_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CamControlButton_C_PreConstruct) == 0x000001, "Wrong alignment on W_CamControlButton_C_PreConstruct");
static_assert(sizeof(W_CamControlButton_C_PreConstruct) == 0x000001, "Wrong size on W_CamControlButton_C_PreConstruct");
static_assert(offsetof(W_CamControlButton_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'W_CamControlButton_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_CamControlButton_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CamControlButton_C_Tick) == 0x000004, "Wrong alignment on W_CamControlButton_C_Tick");
static_assert(sizeof(W_CamControlButton_C_Tick) == 0x00003C, "Wrong size on W_CamControlButton_C_Tick");
static_assert(offsetof(W_CamControlButton_C_Tick, MyGeometry) == 0x000000, "Member 'W_CamControlButton_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Tick, InDeltaTime) == 0x000038, "Member 'W_CamControlButton_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.Update Remote Camera Button
// 0x0208 (0x0208 - 0x0000)
struct W_CamControlButton_C_Update_Remote_Camera_Button final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40AA[0x6];                                     // 0x0002(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	ESQCommandOptionState                         Temp_byte_Variable;                                // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40AB[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable_1;                              // 0x0028(0x0018)()
	class FText                                   Temp_text_Variable_2;                              // 0x0040(0x0018)()
	class FText                                   Temp_text_Variable_3;                              // 0x0058(0x0018)()
	class FText                                   Temp_text_Variable_4;                              // 0x0070(0x0018)()
	class FText                                   Temp_text_Variable_5;                              // 0x0088(0x0018)()
	bool                                          CallFunc_Can_Use_Button_Valid;                     // 0x00A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40AC[0x3];                                     // 0x00A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Temp_float_Variable;                               // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Temp_float_Variable_1;                             // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable_1;                              // 0x00AC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40AD[0x3];                                     // 0x00AD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Select_Default;                             // 0x00B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x00B4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x00B5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40AE[0x2];                                     // 0x00B6(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_CalculateCategoryLocked_ReturnValue;      // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40AF[0x3];                                     // 0x00C1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue; // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQCommandOptionState                         CallFunc_CalculateState_ReturnValue;               // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40B0[0x3];                                     // 0x00C9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_CalculateStatePercentTimeRemaining_ReturnValue; // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00D1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue_1;        // 0x00D2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue_1;                 // 0x00D3(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B1[0x4];                                     // 0x00D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_Select_Default_1;                           // 0x00D8(0x0018)()
	float                                         CallFunc_CalculateStateTimeRemaining_ReturnValue;  // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_SelectFloat_ReturnValue;                  // 0x00F4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimespan                              CallFunc_FromSeconds_ReturnValue;                  // 0x00F8(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x0100(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B2[0x3];                                     // 0x0101(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_BreakTimespan_Days;                       // 0x0104(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Hours;                      // 0x0108(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Minutes;                    // 0x010C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Seconds;                    // 0x0110(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Milliseconds;               // 0x0114(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0118(0x0018)()
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_1;             // 0x0130(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0148(0x0040)(HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x0188(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x01C8(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x01D8(0x0018)()
	class FText                                   K2Node_Select_Default_2;                           // 0x01F0(0x0018)()
};
static_assert(alignof(W_CamControlButton_C_Update_Remote_Camera_Button) == 0x000008, "Wrong alignment on W_CamControlButton_C_Update_Remote_Camera_Button");
static_assert(sizeof(W_CamControlButton_C_Update_Remote_Camera_Button) == 0x000208, "Wrong size on W_CamControlButton_C_Update_Remote_Camera_Button");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_bool_Variable) == 0x000000, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_IsValid_ReturnValue) == 0x000001, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable) == 0x000008, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_byte_Variable) == 0x000020, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable_1) == 0x000028, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable_2) == 0x000040, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable_2' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable_3) == 0x000058, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable_3' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable_4) == 0x000070, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable_4' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_text_Variable_5) == 0x000088, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_text_Variable_5' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_Can_Use_Button_Valid) == 0x0000A0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_Can_Use_Button_Valid' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_float_Variable) == 0x0000A4, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_float_Variable' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_float_Variable_1) == 0x0000A8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_float_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, Temp_bool_Variable_1) == 0x0000AC, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_Select_Default) == 0x0000B0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_IsValid_ReturnValue_1) == 0x0000B4, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_IsValid_ReturnValue_2) == 0x0000B5, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_GetDynamicMaterial_ReturnValue) == 0x0000B8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_CalculateCategoryLocked_ReturnValue) == 0x0000C0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_CalculateCategoryLocked_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue) == 0x0000C4, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_CalculateCategoryCurrentRemainingTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_CalculateState_ReturnValue) == 0x0000C8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_CalculateState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_CalculateStatePercentTimeRemaining_ReturnValue) == 0x0000CC, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_CalculateStatePercentTimeRemaining_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x0000D0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BooleanAND_ReturnValue) == 0x0000D1, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_EqualEqual_ByteByte_ReturnValue_1) == 0x0000D2, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_EqualEqual_ByteByte_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BooleanAND_ReturnValue_1) == 0x0000D3, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BooleanAND_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_Select_Default_1) == 0x0000D8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_CalculateStateTimeRemaining_ReturnValue) == 0x0000F0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_CalculateStateTimeRemaining_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_SelectFloat_ReturnValue) == 0x0000F4, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_SelectFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_FromSeconds_ReturnValue) == 0x0000F8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_FromSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x000100, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BreakTimespan_Days) == 0x000104, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BreakTimespan_Days' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BreakTimespan_Hours) == 0x000108, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BreakTimespan_Hours' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BreakTimespan_Minutes) == 0x00010C, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BreakTimespan_Minutes' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BreakTimespan_Seconds) == 0x000110, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BreakTimespan_Seconds' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_BreakTimespan_Milliseconds) == 0x000114, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_BreakTimespan_Milliseconds' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_Conv_IntToText_ReturnValue) == 0x000118, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_Conv_IntToText_ReturnValue_1) == 0x000130, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_Conv_IntToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_MakeStruct_FormatArgumentData) == 0x000148, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_MakeStruct_FormatArgumentData_1) == 0x000188, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_MakeArray_Array) == 0x0001C8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, CallFunc_Format_ReturnValue) == 0x0001D8, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Update_Remote_Camera_Button, K2Node_Select_Default_2) == 0x0001F0, "Member 'W_CamControlButton_C_Update_Remote_Camera_Button::K2Node_Select_Default_2' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.Can Use Button
// 0x0060 (0x0060 - 0x0000)
struct W_CamControlButton_C_Can_Use_Button final
{
public:
	bool                                          Valid;                                             // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B3[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameState*                           CallFunc_TryGetGameState_OutGameState;             // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetGameState_ReturnValue;              // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Can_Use_Actions_Valid;                    // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B4[0x6];                                     // 0x0012(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Can_Use_Actions_Out_Reason;               // 0x0018(0x0018)()
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B5[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller;        // 0x0038(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B6[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 CallFunc_Get_Command_Action_Condition_Condition_Class; // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_CommanderActionCondition_C*         CallFunc_SpawnObject_ReturnValue;                  // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_CamControlButton_C_Can_Use_Button) == 0x000008, "Wrong alignment on W_CamControlButton_C_Can_Use_Button");
static_assert(sizeof(W_CamControlButton_C_Can_Use_Button) == 0x000060, "Wrong size on W_CamControlButton_C_Can_Use_Button");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, Valid) == 0x000000, "Member 'W_CamControlButton_C_Can_Use_Button::Valid' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_TryGetGameState_OutGameState) == 0x000008, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_TryGetGameState_OutGameState' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_TryGetGameState_ReturnValue) == 0x000010, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_TryGetGameState_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_Can_Use_Actions_Valid) == 0x000011, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_Can_Use_Actions_Valid' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_Can_Use_Actions_Out_Reason) == 0x000018, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_Can_Use_Actions_Out_Reason' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_IsValid_ReturnValue) == 0x000030, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, K2Node_DynamicCast_AsBPI_Player_Controller) == 0x000038, "Member 'W_CamControlButton_C_Can_Use_Button::K2Node_DynamicCast_AsBPI_Player_Controller' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'W_CamControlButton_C_Can_Use_Button::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_Get_Command_Action_Condition_Condition_Class) == 0x000050, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_Get_Command_Action_Condition_Condition_Class' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Can_Use_Button, CallFunc_SpawnObject_ReturnValue) == 0x000058, "Member 'W_CamControlButton_C_Can_Use_Button::CallFunc_SpawnObject_ReturnValue' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.Get Tooltip
// 0x05B0 (0x05B0 - 0x0000)
struct W_CamControlButton_C_Get_Tooltip final
{
public:
	class UWidget*                                ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_Tooltip_C*                         CallFunc_Create_ReturnValue;                       // 0x0008(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Can_Use_Button_Valid;                     // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B7[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQFaction*                             CallFunc_GetFaction_ReturnValue;                   // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_SQFaction_C*                        K2Node_DynamicCast_AsBP_SQFaction;                 // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_TryGetFactionEntry_Success;               // 0x0029(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40B8[0x6];                                     // 0x002A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQFactionEntry                        CallFunc_TryGetFactionEntry_FactionEntry;          // 0x0030(0x0580)(HasGetValueTypeHash)
};
static_assert(alignof(W_CamControlButton_C_Get_Tooltip) == 0x000008, "Wrong alignment on W_CamControlButton_C_Get_Tooltip");
static_assert(sizeof(W_CamControlButton_C_Get_Tooltip) == 0x0005B0, "Wrong size on W_CamControlButton_C_Get_Tooltip");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, ReturnValue) == 0x000000, "Member 'W_CamControlButton_C_Get_Tooltip::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, CallFunc_Create_ReturnValue) == 0x000008, "Member 'W_CamControlButton_C_Get_Tooltip::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, CallFunc_Can_Use_Button_Valid) == 0x000010, "Member 'W_CamControlButton_C_Get_Tooltip::CallFunc_Can_Use_Button_Valid' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, CallFunc_GetFaction_ReturnValue) == 0x000018, "Member 'W_CamControlButton_C_Get_Tooltip::CallFunc_GetFaction_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, K2Node_DynamicCast_AsBP_SQFaction) == 0x000020, "Member 'W_CamControlButton_C_Get_Tooltip::K2Node_DynamicCast_AsBP_SQFaction' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'W_CamControlButton_C_Get_Tooltip::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, CallFunc_TryGetFactionEntry_Success) == 0x000029, "Member 'W_CamControlButton_C_Get_Tooltip::CallFunc_TryGetFactionEntry_Success' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Get_Tooltip, CallFunc_TryGetFactionEntry_FactionEntry) == 0x000030, "Member 'W_CamControlButton_C_Get_Tooltip::CallFunc_TryGetFactionEntry_FactionEntry' has a wrong offset!");

// Function W_CamControlButton.W_CamControlButton_C.Validate Vehicle Action
// 0x0002 (0x0002 - 0x0000)
struct W_CamControlButton_C_Validate_Vehicle_Action final
{
public:
	bool                                          Allowed;                                           // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsInVehicle_ReturnValue;                  // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_CamControlButton_C_Validate_Vehicle_Action) == 0x000001, "Wrong alignment on W_CamControlButton_C_Validate_Vehicle_Action");
static_assert(sizeof(W_CamControlButton_C_Validate_Vehicle_Action) == 0x000002, "Wrong size on W_CamControlButton_C_Validate_Vehicle_Action");
static_assert(offsetof(W_CamControlButton_C_Validate_Vehicle_Action, Allowed) == 0x000000, "Member 'W_CamControlButton_C_Validate_Vehicle_Action::Allowed' has a wrong offset!");
static_assert(offsetof(W_CamControlButton_C_Validate_Vehicle_Action, CallFunc_IsInVehicle_ReturnValue) == 0x000001, "Member 'W_CamControlButton_C_Validate_Vehicle_Action::CallFunc_IsInVehicle_ReturnValue' has a wrong offset!");

}

