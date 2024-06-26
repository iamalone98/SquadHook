#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Marker_Request

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "InputCore_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_Marker_Request.W_Marker_Request_C.ExecuteUbergraph_W_Marker_Request
// 0x0178 (0x0178 - 0x0000)
struct W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel; // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x000A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x000B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BCB[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BCC[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Event_UniformScale;                         // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0020(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0030(0x0008)(NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_PlayerController_C> K2Node_DynamicCast_AsBPI_Player_Controller;        // 0x0040(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0051(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BCD[0x6];                                     // 0x0052(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_GetOwner_ReturnValue_1;                   // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BCE[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_MapMarker_CommandMaster_C*          K2Node_DynamicCast_AsBP_Map_Marker_Command_Master; // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BCF[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0092(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2BD0[0x1];                                     // 0x0093(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0094(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x00D0(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue_1;        // 0x00E0(0x0008)(NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetGameTimeSinceCreation_ReturnValue;     // 0x00E8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x00EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FMax_ReturnValue;                         // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2BD1[0x4];                                     // 0x00F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x00F8(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0110(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0150(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0160(0x0018)()
};
static_assert(alignof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request) == 0x000008, "Wrong alignment on W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request");
static_assert(sizeof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request) == 0x000178, "Wrong size on W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, EntryPoint) == 0x000000, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel) == 0x000004, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_Get_World_Distance_to_Pixel_Distance_Pixel' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, Temp_bool_Variable) == 0x000008, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, Temp_byte_Variable) == 0x000009, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, Temp_byte_Variable_1) == 0x00000A, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_IsValid_ReturnValue) == 0x00000B, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_GetOwner_ReturnValue) == 0x000010, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_IsValid_ReturnValue_1) == 0x000018, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_Event_UniformScale) == 0x00001C, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_Event_UniformScale' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_CreateDelegate_OutputDelegate) == 0x000020, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000030, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_GetOwningPlayer_ReturnValue) == 0x000038, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_AsBPI_Player_Controller) == 0x000040, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_AsBPI_Player_Controller' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_IsValid_ReturnValue_2) == 0x000051, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_GetOwner_ReturnValue_1) == 0x000058, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_GetOwner_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_IsValid_ReturnValue_3) == 0x000060, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_AsBP_Map_Marker_Command_Master) == 0x000068, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_AsBP_Map_Marker_Command_Master' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_bSuccess_1) == 0x000070, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_PlayAnimation_ReturnValue) == 0x000078, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x000080, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000088, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_DynamicCast_bSuccess_2) == 0x000090, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_IsCommander_ReturnValue) == 0x000091, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_IsCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_Select_Default) == 0x000092, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_Event_MyGeometry) == 0x000094, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_Event_InDeltaTime) == 0x0000CC, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_CreateDelegate_OutputDelegate_1) == 0x0000D0, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_K2_SetTimerDelegate_ReturnValue_1) == 0x0000E0, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_K2_SetTimerDelegate_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_GetGameTimeSinceCreation_ReturnValue) == 0x0000E8, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_GetGameTimeSinceCreation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x0000EC, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_FMax_ReturnValue) == 0x0000F0, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_FMax_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_Conv_FloatToText_ReturnValue) == 0x0000F8, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_MakeStruct_FormatArgumentData) == 0x000110, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, K2Node_MakeArray_Array) == 0x000150, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request, CallFunc_Format_ReturnValue) == 0x000160, "Member 'W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function W_Marker_Request.W_Marker_Request_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_Marker_Request_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Marker_Request_C_Tick) == 0x000004, "Wrong alignment on W_Marker_Request_C_Tick");
static_assert(sizeof(W_Marker_Request_C_Tick) == 0x00003C, "Wrong size on W_Marker_Request_C_Tick");
static_assert(offsetof(W_Marker_Request_C_Tick, MyGeometry) == 0x000000, "Member 'W_Marker_Request_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_Tick, InDeltaTime) == 0x000038, "Member 'W_Marker_Request_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_Marker_Request.W_Marker_Request_C.OnScaleChanged
// 0x0004 (0x0004 - 0x0000)
struct W_Marker_Request_C_OnScaleChanged final
{
public:
	float                                         UniformScale;                                      // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Marker_Request_C_OnScaleChanged) == 0x000004, "Wrong alignment on W_Marker_Request_C_OnScaleChanged");
static_assert(sizeof(W_Marker_Request_C_OnScaleChanged) == 0x000004, "Wrong size on W_Marker_Request_C_OnScaleChanged");
static_assert(offsetof(W_Marker_Request_C_OnScaleChanged, UniformScale) == 0x000000, "Member 'W_Marker_Request_C_OnScaleChanged::UniformScale' has a wrong offset!");

// Function W_Marker_Request.W_Marker_Request_C.OnPreviewMouseButtonDown
// 0x03D8 (0x03D8 - 0x0000)
struct W_Marker_Request_C_OnPreviewMouseButtonDown final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	struct FKey                                   CallFunc_PointerEvent_GetEffectingButton_ReturnValue; // 0x0160(0x0018)(HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0178(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_KeyKey_ReturnValue;            // 0x0179(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD2[0x2];                                     // 0x017A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Array_Index_Variable;                     // 0x017C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0180(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0184(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0188(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0190(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD3[0x7];                                     // 0x0191(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0198(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x01A0(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x01B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x01B1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x01B2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD4[0x5];                                     // 0x01B3(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UW_CommandRequestList_C*>        CallFunc_GetAllWidgetsOfClass_FoundWidgets;        // 0x01B8(0x0010)(ReferenceParm, ContainsInstancedReference)
	class UW_CommandRequestList_C*                CallFunc_Array_Get_Item;                           // 0x01C8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x01D0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x01D4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD5[0x3];                                     // 0x01D5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector2D                              CallFunc_PointerEvent_GetScreenSpacePosition_ReturnValue; // 0x01D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Mouse_Position_to_World_Location_ReturnValue; // 0x01E0(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2BD6[0x4];                                     // 0x01EC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_MapMarker_Command_Request_C*        K2Node_DynamicCast_AsBP_Map_Marker_Command_Request; // 0x01F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x01F8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD7[0x3];                                     // 0x01F9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_RebaseLocalOriginOntoZero_ReturnValue;    // 0x01FC(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0208(0x00B8)()
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_1;            // 0x02C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetMousePositionScaledByDPI_LocationX;    // 0x02C8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetMousePositionScaledByDPI_LocationY;    // 0x02CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetMousePositionScaledByDPI_ReturnValue;  // 0x02D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD8[0x7];                                     // 0x02D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_2;            // 0x02D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x02E0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_CommandRequestList_C*                CallFunc_Create_ReturnValue;                       // 0x02E8(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue_3;            // 0x02F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AHUD*                                   CallFunc_GetHUD_ReturnValue_1;                     // 0x02F8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD_1;                    // 0x0300(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0310(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BD9[0x7];                                     // 0x0311(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SQMapCore_C*                         CallFunc_Get_Map_Core_Map_Core;                    // 0x0318(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0320(0x00B8)()
};
static_assert(alignof(W_Marker_Request_C_OnPreviewMouseButtonDown) == 0x000008, "Wrong alignment on W_Marker_Request_C_OnPreviewMouseButtonDown");
static_assert(sizeof(W_Marker_Request_C_OnPreviewMouseButtonDown) == 0x0003D8, "Wrong size on W_Marker_Request_C_OnPreviewMouseButtonDown");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, MyGeometry) == 0x000000, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, MouseEvent) == 0x000038, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, ReturnValue) == 0x0000A8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_PointerEvent_GetEffectingButton_ReturnValue) == 0x000160, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_PointerEvent_GetEffectingButton_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_IsValid_ReturnValue) == 0x000178, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_EqualEqual_KeyKey_ReturnValue) == 0x000179, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_EqualEqual_KeyKey_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, Temp_int_Array_Index_Variable) == 0x00017C, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, Temp_int_Loop_Counter_Variable) == 0x000180, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Add_IntInt_ReturnValue) == 0x000184, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetOwningPlayer_ReturnValue) == 0x000188, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_IsValid_ReturnValue_1) == 0x000190, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetHUD_ReturnValue) == 0x000198, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_AsBPI_HUD) == 0x0001A0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_bSuccess) == 0x0001B0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_IsCommander_ReturnValue) == 0x0001B1, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_IsCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Not_PreBool_ReturnValue) == 0x0001B2, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetAllWidgetsOfClass_FoundWidgets) == 0x0001B8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetAllWidgetsOfClass_FoundWidgets' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Array_Get_Item) == 0x0001C8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Array_Length_ReturnValue) == 0x0001D0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Less_IntInt_ReturnValue) == 0x0001D4, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_PointerEvent_GetScreenSpacePosition_ReturnValue) == 0x0001D8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_PointerEvent_GetScreenSpacePosition_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Mouse_Position_to_World_Location_ReturnValue) == 0x0001E0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Mouse_Position_to_World_Location_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_AsBP_Map_Marker_Command_Request) == 0x0001F0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_AsBP_Map_Marker_Command_Request' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_bSuccess_1) == 0x0001F8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_RebaseLocalOriginOntoZero_ReturnValue) == 0x0001FC, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_RebaseLocalOriginOntoZero_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Unhandled_ReturnValue) == 0x000208, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Unhandled_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetOwningPlayer_ReturnValue_1) == 0x0002C0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetOwningPlayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetMousePositionScaledByDPI_LocationX) == 0x0002C8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetMousePositionScaledByDPI_LocationX' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetMousePositionScaledByDPI_LocationY) == 0x0002CC, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetMousePositionScaledByDPI_LocationY' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetMousePositionScaledByDPI_ReturnValue) == 0x0002D0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetMousePositionScaledByDPI_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetOwningPlayer_ReturnValue_2) == 0x0002D8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetOwningPlayer_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_MakeVector2D_ReturnValue) == 0x0002E0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Create_ReturnValue) == 0x0002E8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetOwningPlayer_ReturnValue_3) == 0x0002F0, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetOwningPlayer_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_GetHUD_ReturnValue_1) == 0x0002F8, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_GetHUD_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_AsBPI_HUD_1) == 0x000300, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_AsBPI_HUD_1' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, K2Node_DynamicCast_bSuccess_2) == 0x000310, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Get_Map_Core_Map_Core) == 0x000318, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Get_Map_Core_Map_Core' has a wrong offset!");
static_assert(offsetof(W_Marker_Request_C_OnPreviewMouseButtonDown, CallFunc_Handled_ReturnValue) == 0x000320, "Member 'W_Marker_Request_C_OnPreviewMouseButtonDown::CallFunc_Handled_ReturnValue' has a wrong offset!");

}

