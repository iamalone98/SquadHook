#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_Slider_LR

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.OnValueChanged__DelegateSignature
// 0x0004 (0x0004 - 0x0000)
struct SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature final
{
public:
	float                                         Param_Value;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature) == 0x000004, "Wrong alignment on SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature");
static_assert(sizeof(SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature) == 0x000004, "Wrong size on SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature");
static_assert(offsetof(SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature, Param_Value) == 0x000000, "Member 'SettingsItem_Slider_LR_C_OnValueChanged__DelegateSignature::Param_Value' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.OnCaptureEnd__DelegateSignature
// 0x0004 (0x0004 - 0x0000)
struct SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature final
{
public:
	float                                         Param_Value;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature) == 0x000004, "Wrong alignment on SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature");
static_assert(sizeof(SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature) == 0x000004, "Wrong size on SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature");
static_assert(offsetof(SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature, Param_Value) == 0x000000, "Member 'SettingsItem_Slider_LR_C_OnCaptureEnd__DelegateSignature::Param_Value' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.ExecuteUbergraph_SettingsItem_Slider_LR
// 0x0110 (0x0110 - 0x0000)
struct SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_315A[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	float                                         K2Node_ComponentBoundEvent_Value;                  // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_315B[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_ComponentBoundEvent_Text_1;                 // 0x0028(0x0018)(ConstParm)
	float                                         CallFunc_MapRangeUnclamped_ReturnValue;            // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_315C[0x4];                                     // 0x0044(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_RemovePercentage_OutText;                 // 0x0048(0x0018)()
	bool                                          CallFunc_TextIsEmpty_ReturnValue;                  // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_315D[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_TextToString_ReturnValue;            // 0x0068(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Conv_TextToString_ReturnValue_1;          // 0x0078(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsNumeric_ReturnValue;                    // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_315E[0x3];                                     // 0x0089(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Len_ReturnValue;                          // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_315F[0x6];                                     // 0x0092(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_Select_Default;                             // 0x0098(0x0018)()
	class FText                                   K2Node_ComponentBoundEvent_Text;                   // 0x00B0(0x0018)(ConstParm)
	ETextCommit                                   K2Node_ComponentBoundEvent_CommitMethod;           // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3160[0x7];                                     // 0x00C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_RemovePercentage_OutText_1;               // 0x00D0(0x0018)()
	class FString                                 CallFunc_Conv_TextToString_ReturnValue_2;          // 0x00E8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_StringToFloat_ReturnValue;           // 0x00F8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsNumeric_ReturnValue_1;                  // 0x00FC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3161[0x3];                                     // 0x00FD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0100(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0104(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3162[0x3];                                     // 0x0105(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetValue_ReturnValue;                     // 0x0108(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_MapRangeUnclamped_ReturnValue_1;          // 0x010C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR");
static_assert(sizeof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR) == 0x000110, "Wrong size on SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, EntryPoint) == 0x000000, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::EntryPoint' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, Temp_bool_Variable) == 0x000004, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, Temp_text_Variable) == 0x000008, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_ComponentBoundEvent_Value) == 0x000020, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_ComponentBoundEvent_Value' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_ComponentBoundEvent_Text_1) == 0x000028, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_ComponentBoundEvent_Text_1' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_MapRangeUnclamped_ReturnValue) == 0x000040, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_MapRangeUnclamped_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_RemovePercentage_OutText) == 0x000048, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_RemovePercentage_OutText' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_TextIsEmpty_ReturnValue) == 0x000060, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_TextIsEmpty_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Conv_TextToString_ReturnValue) == 0x000068, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Conv_TextToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Conv_TextToString_ReturnValue_1) == 0x000078, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Conv_TextToString_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_IsNumeric_ReturnValue) == 0x000088, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_IsNumeric_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Len_ReturnValue) == 0x00008C, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Len_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Less_IntInt_ReturnValue) == 0x000090, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_BooleanAND_ReturnValue) == 0x000091, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_Select_Default) == 0x000098, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_ComponentBoundEvent_Text) == 0x0000B0, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_ComponentBoundEvent_Text' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_ComponentBoundEvent_CommitMethod) == 0x0000C8, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_ComponentBoundEvent_CommitMethod' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_RemovePercentage_OutText_1) == 0x0000D0, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_RemovePercentage_OutText_1' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Conv_TextToString_ReturnValue_2) == 0x0000E8, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Conv_TextToString_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_Conv_StringToFloat_ReturnValue) == 0x0000F8, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_Conv_StringToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_IsNumeric_ReturnValue_1) == 0x0000FC, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_IsNumeric_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_FClamp_ReturnValue) == 0x000100, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, K2Node_Event_IsDesignTime) == 0x000104, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_GetValue_ReturnValue) == 0x000108, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_GetValue_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR, CallFunc_MapRangeUnclamped_ReturnValue_1) == 0x00010C, "Member 'SettingsItem_Slider_LR_C_ExecuteUbergraph_SettingsItem_Slider_LR::CallFunc_MapRangeUnclamped_ReturnValue_1' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct SettingsItem_Slider_LR_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(SettingsItem_Slider_LR_C_PreConstruct) == 0x000001, "Wrong alignment on SettingsItem_Slider_LR_C_PreConstruct");
static_assert(sizeof(SettingsItem_Slider_LR_C_PreConstruct) == 0x000001, "Wrong size on SettingsItem_Slider_LR_C_PreConstruct");
static_assert(offsetof(SettingsItem_Slider_LR_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'SettingsItem_Slider_LR_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature
// 0x0020 (0x0020 - 0x0000)
struct SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature final
{
public:
	class FText                                   Text;                                              // 0x0000(0x0018)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	ETextCommit                                   CommitMethod;                                      // 0x0018(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature");
static_assert(sizeof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature) == 0x000020, "Wrong size on SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature");
static_assert(offsetof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature, Text) == 0x000000, "Member 'SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature::Text' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature, CommitMethod) == 0x000018, "Member 'SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature::CommitMethod' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature
// 0x0018 (0x0018 - 0x0000)
struct SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature final
{
public:
	class FText                                   Text;                                              // 0x0000(0x0018)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
};
static_assert(alignof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature");
static_assert(sizeof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature) == 0x000018, "Wrong size on SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature");
static_assert(offsetof(SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature, Text) == 0x000000, "Member 'SettingsItem_Slider_LR_C_BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature::Text' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature
// 0x0004 (0x0004 - 0x0000)
struct SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature final
{
public:
	float                                         Param_Value;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature) == 0x000004, "Wrong alignment on SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature");
static_assert(sizeof(SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature) == 0x000004, "Wrong size on SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature");
static_assert(offsetof(SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature, Param_Value) == 0x000000, "Member 'SettingsItem_Slider_LR_C_BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature::Param_Value' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.SetValue
// 0x0004 (0x0004 - 0x0000)
struct SettingsItem_Slider_LR_C_SetValue final
{
public:
	float                                         Param_Value;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_SetValue) == 0x000004, "Wrong alignment on SettingsItem_Slider_LR_C_SetValue");
static_assert(sizeof(SettingsItem_Slider_LR_C_SetValue) == 0x000004, "Wrong size on SettingsItem_Slider_LR_C_SetValue");
static_assert(offsetof(SettingsItem_Slider_LR_C_SetValue, Param_Value) == 0x000000, "Member 'SettingsItem_Slider_LR_C_SetValue::Param_Value' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.UpdateSliderTextValue
// 0x0080 (0x0080 - 0x0000)
struct SettingsItem_Slider_LR_C_UpdateSliderTextValue final
{
public:
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0000(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0018(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0058(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0068(0x0018)()
};
static_assert(alignof(SettingsItem_Slider_LR_C_UpdateSliderTextValue) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_UpdateSliderTextValue");
static_assert(sizeof(SettingsItem_Slider_LR_C_UpdateSliderTextValue) == 0x000080, "Wrong size on SettingsItem_Slider_LR_C_UpdateSliderTextValue");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderTextValue, CallFunc_Conv_FloatToText_ReturnValue) == 0x000000, "Member 'SettingsItem_Slider_LR_C_UpdateSliderTextValue::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderTextValue, K2Node_MakeStruct_FormatArgumentData) == 0x000018, "Member 'SettingsItem_Slider_LR_C_UpdateSliderTextValue::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderTextValue, K2Node_MakeArray_Array) == 0x000058, "Member 'SettingsItem_Slider_LR_C_UpdateSliderTextValue::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderTextValue, CallFunc_Format_ReturnValue) == 0x000068, "Member 'SettingsItem_Slider_LR_C_UpdateSliderTextValue::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.UpdateSliderValue
// 0x0008 (0x0008 - 0x0000)
struct SettingsItem_Slider_LR_C_UpdateSliderValue final
{
public:
	float                                         CallFunc_MapRangeUnclamped_ReturnValue;            // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SettingsItem_Slider_LR_C_UpdateSliderValue) == 0x000004, "Wrong alignment on SettingsItem_Slider_LR_C_UpdateSliderValue");
static_assert(sizeof(SettingsItem_Slider_LR_C_UpdateSliderValue) == 0x000008, "Wrong size on SettingsItem_Slider_LR_C_UpdateSliderValue");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderValue, CallFunc_MapRangeUnclamped_ReturnValue) == 0x000000, "Member 'SettingsItem_Slider_LR_C_UpdateSliderValue::CallFunc_MapRangeUnclamped_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_UpdateSliderValue, CallFunc_FClamp_ReturnValue) == 0x000004, "Member 'SettingsItem_Slider_LR_C_UpdateSliderValue::CallFunc_FClamp_ReturnValue' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.Get_SpacerImg_Brush_0
// 0x0138 (0x0138 - 0x0000)
struct SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0 final
{
public:
	struct FSlateBrush                            ReturnValue;                                       // 0x0000(0x0088)(Parm, OutParm, ReturnParm)
	struct FVector2D                              CallFunc_GetViewportSize_ReturnValue;              // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X;                          // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush;                      // 0x00B0(0x0088)()
};
static_assert(alignof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0");
static_assert(sizeof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0) == 0x000138, "Wrong size on SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, ReturnValue) == 0x000000, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_GetViewportSize_ReturnValue) == 0x000088, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_GetViewportSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_BreakVector2D_X) == 0x000090, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_BreakVector2D_Y) == 0x000094, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000098, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_Divide_FloatFloat_ReturnValue) == 0x00009C, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_FClamp_ReturnValue) == 0x0000A0, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0000A4, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, CallFunc_MakeVector2D_ReturnValue) == 0x0000A8, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0, K2Node_MakeStruct_SlateBrush) == 0x0000B0, "Member 'SettingsItem_Slider_LR_C_Get_SpacerImg_Brush_0::K2Node_MakeStruct_SlateBrush' has a wrong offset!");

// Function SettingsItem_Slider_LR.SettingsItem_Slider_LR_C.RemovePercentage
// 0x0068 (0x0068 - 0x0000)
struct SettingsItem_Slider_LR_C_RemovePercentage final
{
public:
	class FText                                   InText;                                            // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
	class FText                                   OutText;                                           // 0x0018(0x0018)(Parm, OutParm)
	class FString                                 CallFunc_Conv_TextToString_ReturnValue;            // 0x0030(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Replace_ReturnValue;                      // 0x0040(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0050(0x0018)()
};
static_assert(alignof(SettingsItem_Slider_LR_C_RemovePercentage) == 0x000008, "Wrong alignment on SettingsItem_Slider_LR_C_RemovePercentage");
static_assert(sizeof(SettingsItem_Slider_LR_C_RemovePercentage) == 0x000068, "Wrong size on SettingsItem_Slider_LR_C_RemovePercentage");
static_assert(offsetof(SettingsItem_Slider_LR_C_RemovePercentage, InText) == 0x000000, "Member 'SettingsItem_Slider_LR_C_RemovePercentage::InText' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_RemovePercentage, OutText) == 0x000018, "Member 'SettingsItem_Slider_LR_C_RemovePercentage::OutText' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_RemovePercentage, CallFunc_Conv_TextToString_ReturnValue) == 0x000030, "Member 'SettingsItem_Slider_LR_C_RemovePercentage::CallFunc_Conv_TextToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_RemovePercentage, CallFunc_Replace_ReturnValue) == 0x000040, "Member 'SettingsItem_Slider_LR_C_RemovePercentage::CallFunc_Replace_ReturnValue' has a wrong offset!");
static_assert(offsetof(SettingsItem_Slider_LR_C_RemovePercentage, CallFunc_Conv_StringToText_ReturnValue) == 0x000050, "Member 'SettingsItem_Slider_LR_C_RemovePercentage::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");

}

