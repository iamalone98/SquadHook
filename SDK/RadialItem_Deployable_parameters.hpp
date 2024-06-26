#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialItem_Deployable

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "SQUnavailabilityReason_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function RadialItem_Deployable.RadialItem_Deployable_C.ExecuteUbergraph_RadialItem_Deployable
// 0x0048 (0x0048 - 0x0000)
struct RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue;      // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable) == 0x000004, "Wrong alignment on RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable");
static_assert(sizeof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable) == 0x000048, "Wrong size on RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable");
static_assert(offsetof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable, EntryPoint) == 0x000000, "Member 'RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable::EntryPoint' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable, K2Node_Event_MyGeometry) == 0x000004, "Member 'RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable, CallFunc_Add_FloatFloat_ReturnValue) == 0x000040, "Member 'RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable, CallFunc_GreaterEqual_FloatFloat_ReturnValue) == 0x000044, "Member 'RadialItem_Deployable_C_ExecuteUbergraph_RadialItem_Deployable::CallFunc_GreaterEqual_FloatFloat_ReturnValue' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.Tick
// 0x003C (0x003C - 0x0000)
struct RadialItem_Deployable_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(RadialItem_Deployable_C_Tick) == 0x000004, "Wrong alignment on RadialItem_Deployable_C_Tick");
static_assert(sizeof(RadialItem_Deployable_C_Tick) == 0x00003C, "Wrong size on RadialItem_Deployable_C_Tick");
static_assert(offsetof(RadialItem_Deployable_C_Tick, MyGeometry) == 0x000000, "Member 'RadialItem_Deployable_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_Tick, InDeltaTime) == 0x000038, "Member 'RadialItem_Deployable_C_Tick::InDeltaTime' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.UpdateAvailabilityStatus
// 0x0070 (0x0070 - 0x0000)
struct RadialItem_Deployable_C_UpdateAvailabilityStatus final
{
public:
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_PlayerController_C*                 K2Node_DynamicCast_AsBP_Player_Controller;         // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0012(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E90[0x5];                                     // 0x0013(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Deployable        CallFunc_TryGetDeployableAvailability_OutUpdatedDeployableState; // 0x0018(0x0050)(ContainsInstancedReference)
	bool                                          CallFunc_TryGetDeployableAvailability_ReturnValue; // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialItem_Deployable_C_UpdateAvailabilityStatus) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_UpdateAvailabilityStatus");
static_assert(sizeof(RadialItem_Deployable_C_UpdateAvailabilityStatus) == 0x000070, "Wrong size on RadialItem_Deployable_C_UpdateAvailabilityStatus");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, CallFunc_GetOwningPlayer_ReturnValue) == 0x000000, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, K2Node_DynamicCast_AsBP_Player_Controller) == 0x000008, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::K2Node_DynamicCast_AsBP_Player_Controller' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, CallFunc_IsValid_ReturnValue_1) == 0x000012, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, CallFunc_TryGetDeployableAvailability_OutUpdatedDeployableState) == 0x000018, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::CallFunc_TryGetDeployableAvailability_OutUpdatedDeployableState' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_UpdateAvailabilityStatus, CallFunc_TryGetDeployableAvailability_ReturnValue) == 0x000068, "Member 'RadialItem_Deployable_C_UpdateAvailabilityStatus::CallFunc_TryGetDeployableAvailability_ReturnValue' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.IsAvailable
// 0x0070 (0x0070 - 0x0000)
struct RadialItem_Deployable_C_IsAvailable final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E91[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E92[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState                   CallFunc_IsDeployableAvailableForPlayer_OutPlayerState; // 0x0020(0x0048)()
	bool                                          CallFunc_IsDeployableAvailableForPlayer_ReturnValue; // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialItem_Deployable_C_IsAvailable) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_IsAvailable");
static_assert(sizeof(RadialItem_Deployable_C_IsAvailable) == 0x000070, "Wrong size on RadialItem_Deployable_C_IsAvailable");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, ReturnValue) == 0x000000, "Member 'RadialItem_Deployable_C_IsAvailable::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'RadialItem_Deployable_C_IsAvailable::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000010, "Member 'RadialItem_Deployable_C_IsAvailable::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'RadialItem_Deployable_C_IsAvailable::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, CallFunc_IsDeployableAvailableForPlayer_OutPlayerState) == 0x000020, "Member 'RadialItem_Deployable_C_IsAvailable::CallFunc_IsDeployableAvailableForPlayer_OutPlayerState' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_IsAvailable, CallFunc_IsDeployableAvailableForPlayer_ReturnValue) == 0x000068, "Member 'RadialItem_Deployable_C_IsAvailable::CallFunc_IsDeployableAvailableForPlayer_ReturnValue' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.GetDetailText
// 0x0068 (0x0068 - 0x0000)
struct RadialItem_Deployable_C_GetDetailText final
{
public:
	class FText                                   DetailText;                                        // 0x0000(0x0018)(Parm, OutParm)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasDeployableActiveTimer_ReturnValue;     // 0x0029(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E93[0x6];                                     // 0x002A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetTimerText_ReturnValue;                 // 0x0030(0x0018)()
	bool                                          CallFunc_HasLimitedCount_ReturnValue;              // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E94[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetAvailabilityText_ReturnValue;          // 0x0050(0x0018)()
};
static_assert(alignof(RadialItem_Deployable_C_GetDetailText) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_GetDetailText");
static_assert(sizeof(RadialItem_Deployable_C_GetDetailText) == 0x000068, "Wrong size on RadialItem_Deployable_C_GetDetailText");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, DetailText) == 0x000000, "Member 'RadialItem_Deployable_C_GetDetailText::DetailText' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, CallFunc_GetOwningPlayer_ReturnValue) == 0x000018, "Member 'RadialItem_Deployable_C_GetDetailText::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000020, "Member 'RadialItem_Deployable_C_GetDetailText::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'RadialItem_Deployable_C_GetDetailText::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, CallFunc_HasDeployableActiveTimer_ReturnValue) == 0x000029, "Member 'RadialItem_Deployable_C_GetDetailText::CallFunc_HasDeployableActiveTimer_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, CallFunc_GetTimerText_ReturnValue) == 0x000030, "Member 'RadialItem_Deployable_C_GetDetailText::CallFunc_GetTimerText_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, CallFunc_HasLimitedCount_ReturnValue) == 0x000048, "Member 'RadialItem_Deployable_C_GetDetailText::CallFunc_HasLimitedCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetDetailText, CallFunc_GetAvailabilityText_ReturnValue) == 0x000050, "Member 'RadialItem_Deployable_C_GetDetailText::CallFunc_GetAvailabilityText_ReturnValue' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.ConvertTimerToText
// 0x0260 (0x0260 - 0x0000)
struct RadialItem_Deployable_C_ConvertTimerToText final
{
public:
	struct FTimespan                              InTimespan;                                        // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	class FText                                   ReturnValue;                                       // 0x0008(0x0018)(Parm, OutParm, ReturnParm)
	bool                                          Temp_bool_Variable;                                // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E95[0x3];                                     // 0x0021(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_BreakTimespan_Days;                       // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Hours;                      // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Minutes;                    // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Seconds;                    // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_BreakTimespan_Milliseconds;               // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E96[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0040(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0058(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_1;             // 0x0098(0x0018)()
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_2;             // 0x00B0(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00C8(0x0040)(HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_2;            // 0x0108(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_3;             // 0x0148(0x0018)()
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0160(0x0010)(ReferenceParm)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_3;            // 0x0170(0x0040)(HasGetValueTypeHash)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x01B0(0x0018)()
	class FText                                   CallFunc_Conv_IntToText_ReturnValue_4;             // 0x01C8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_4;            // 0x01E0(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x0220(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x0230(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0248(0x0018)()
};
static_assert(alignof(RadialItem_Deployable_C_ConvertTimerToText) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_ConvertTimerToText");
static_assert(sizeof(RadialItem_Deployable_C_ConvertTimerToText) == 0x000260, "Wrong size on RadialItem_Deployable_C_ConvertTimerToText");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, InTimespan) == 0x000000, "Member 'RadialItem_Deployable_C_ConvertTimerToText::InTimespan' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, ReturnValue) == 0x000008, "Member 'RadialItem_Deployable_C_ConvertTimerToText::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, Temp_bool_Variable) == 0x000020, "Member 'RadialItem_Deployable_C_ConvertTimerToText::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_BreakTimespan_Days) == 0x000024, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_BreakTimespan_Days' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_BreakTimespan_Hours) == 0x000028, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_BreakTimespan_Hours' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_BreakTimespan_Minutes) == 0x00002C, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_BreakTimespan_Minutes' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_BreakTimespan_Seconds) == 0x000030, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_BreakTimespan_Seconds' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_BreakTimespan_Milliseconds) == 0x000034, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_BreakTimespan_Milliseconds' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Greater_IntInt_ReturnValue) == 0x000038, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Conv_IntToText_ReturnValue) == 0x000040, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeStruct_FormatArgumentData) == 0x000058, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Conv_IntToText_ReturnValue_1) == 0x000098, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Conv_IntToText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Conv_IntToText_ReturnValue_2) == 0x0000B0, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Conv_IntToText_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000C8, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeStruct_FormatArgumentData_2) == 0x000108, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeStruct_FormatArgumentData_2' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Conv_IntToText_ReturnValue_3) == 0x000148, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Conv_IntToText_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeArray_Array) == 0x000160, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeStruct_FormatArgumentData_3) == 0x000170, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeStruct_FormatArgumentData_3' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Format_ReturnValue) == 0x0001B0, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Conv_IntToText_ReturnValue_4) == 0x0001C8, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Conv_IntToText_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeStruct_FormatArgumentData_4) == 0x0001E0, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeStruct_FormatArgumentData_4' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_MakeArray_Array_1) == 0x000220, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, CallFunc_Format_ReturnValue_1) == 0x000230, "Member 'RadialItem_Deployable_C_ConvertTimerToText::CallFunc_Format_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_ConvertTimerToText, K2Node_Select_Default) == 0x000248, "Member 'RadialItem_Deployable_C_ConvertTimerToText::K2Node_Select_Default' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.GetTimerText
// 0x0088 (0x0088 - 0x0000)
struct RadialItem_Deployable_C_GetTimerText final
{
public:
	struct FSQAvailabilityState                   SQAvailabilityState;                               // 0x0000(0x0048)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	class FText                                   ReturnValue;                                       // 0x0048(0x0018)(Parm, OutParm, ReturnParm)
	struct FDateTime                              CallFunc_GetServerUtcTime_ReturnValue;             // 0x0060(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	struct FTimespan                              CallFunc_Subtract_DateTimeDateTime_ReturnValue;    // 0x0068(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_ConvertTimerToText_ReturnValue;           // 0x0070(0x0018)()
};
static_assert(alignof(RadialItem_Deployable_C_GetTimerText) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_GetTimerText");
static_assert(sizeof(RadialItem_Deployable_C_GetTimerText) == 0x000088, "Wrong size on RadialItem_Deployable_C_GetTimerText");
static_assert(offsetof(RadialItem_Deployable_C_GetTimerText, SQAvailabilityState) == 0x000000, "Member 'RadialItem_Deployable_C_GetTimerText::SQAvailabilityState' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetTimerText, ReturnValue) == 0x000048, "Member 'RadialItem_Deployable_C_GetTimerText::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetTimerText, CallFunc_GetServerUtcTime_ReturnValue) == 0x000060, "Member 'RadialItem_Deployable_C_GetTimerText::CallFunc_GetServerUtcTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetTimerText, CallFunc_Subtract_DateTimeDateTime_ReturnValue) == 0x000068, "Member 'RadialItem_Deployable_C_GetTimerText::CallFunc_Subtract_DateTimeDateTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetTimerText, CallFunc_ConvertTimerToText_ReturnValue) == 0x000070, "Member 'RadialItem_Deployable_C_GetTimerText::CallFunc_ConvertTimerToText_ReturnValue' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.GetAvailabilityText
// 0x0120 (0x0120 - 0x0000)
struct RadialItem_Deployable_C_GetAvailabilityText final
{
public:
	struct FSQAvailabilityState                   SQAvailabilityState;                               // 0x0000(0x0048)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	bool                                          In_HasLimitedCount;                                // 0x0048(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E97[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   ReturnValue;                                       // 0x0050(0x0018)(Parm, OutParm, ReturnParm)
	class FString                                 Temp_string_Variable;                              // 0x0068(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsAvailable_ReturnValue;                  // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E98[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_IntToString_ReturnValue;             // 0x0080(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E99[0x7];                                     // 0x0091(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Concat_StrStr_ReturnValue;                // 0x0098(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanOR_ReturnValue;                    // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E9A[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x00B0(0x0018)()
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue_1;          // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E9B[0x7];                                     // 0x00C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_IntToString_ReturnValue_1;           // 0x00D0(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x00E0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3E9C[0x7];                                     // 0x00E1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 K2Node_Select_Default;                             // 0x00E8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FString                                 CallFunc_Concat_StrStr_ReturnValue_1;              // 0x00F8(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue_1;          // 0x0108(0x0018)()
};
static_assert(alignof(RadialItem_Deployable_C_GetAvailabilityText) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_GetAvailabilityText");
static_assert(sizeof(RadialItem_Deployable_C_GetAvailabilityText) == 0x000120, "Wrong size on RadialItem_Deployable_C_GetAvailabilityText");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, SQAvailabilityState) == 0x000000, "Member 'RadialItem_Deployable_C_GetAvailabilityText::SQAvailabilityState' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, In_HasLimitedCount) == 0x000048, "Member 'RadialItem_Deployable_C_GetAvailabilityText::In_HasLimitedCount' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, ReturnValue) == 0x000050, "Member 'RadialItem_Deployable_C_GetAvailabilityText::ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, Temp_string_Variable) == 0x000068, "Member 'RadialItem_Deployable_C_GetAvailabilityText::Temp_string_Variable' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_IsAvailable_ReturnValue) == 0x000078, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_IsAvailable_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Conv_IntToString_ReturnValue) == 0x000080, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Conv_IntToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000090, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Concat_StrStr_ReturnValue) == 0x000098, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Concat_StrStr_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_BooleanOR_ReturnValue) == 0x0000A8, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_BooleanOR_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Conv_StringToText_ReturnValue) == 0x0000B0, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_EqualEqual_IntInt_ReturnValue_1) == 0x0000C8, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_EqualEqual_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Conv_IntToString_ReturnValue_1) == 0x0000D0, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Conv_IntToString_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, Temp_bool_Variable) == 0x0000E0, "Member 'RadialItem_Deployable_C_GetAvailabilityText::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, K2Node_Select_Default) == 0x0000E8, "Member 'RadialItem_Deployable_C_GetAvailabilityText::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Concat_StrStr_ReturnValue_1) == 0x0000F8, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Concat_StrStr_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetAvailabilityText, CallFunc_Conv_StringToText_ReturnValue_1) == 0x000108, "Member 'RadialItem_Deployable_C_GetAvailabilityText::CallFunc_Conv_StringToText_ReturnValue_1' has a wrong offset!");

// Function RadialItem_Deployable.RadialItem_Deployable_C.GetUnavailabilityReason
// 0x00C0 (0x00C0 - 0x0000)
struct RadialItem_Deployable_C_GetUnavailabilityReason final
{
public:
	struct FSQAvailabilityState                   SQAvailabilityState;                               // 0x0000(0x0048)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	class FText                                   Return_Value;                                      // 0x0048(0x0018)(Parm, OutParm)
	struct FSQUnavailabilityReason                CallFunc_GetDataTableRowFromName_OutRow;           // 0x0060(0x0058)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x00B8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(RadialItem_Deployable_C_GetUnavailabilityReason) == 0x000008, "Wrong alignment on RadialItem_Deployable_C_GetUnavailabilityReason");
static_assert(sizeof(RadialItem_Deployable_C_GetUnavailabilityReason) == 0x0000C0, "Wrong size on RadialItem_Deployable_C_GetUnavailabilityReason");
static_assert(offsetof(RadialItem_Deployable_C_GetUnavailabilityReason, SQAvailabilityState) == 0x000000, "Member 'RadialItem_Deployable_C_GetUnavailabilityReason::SQAvailabilityState' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetUnavailabilityReason, Return_Value) == 0x000048, "Member 'RadialItem_Deployable_C_GetUnavailabilityReason::Return_Value' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetUnavailabilityReason, CallFunc_GetDataTableRowFromName_OutRow) == 0x000060, "Member 'RadialItem_Deployable_C_GetUnavailabilityReason::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(RadialItem_Deployable_C_GetUnavailabilityReason, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x0000B8, "Member 'RadialItem_Deployable_C_GetUnavailabilityReason::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");

}

