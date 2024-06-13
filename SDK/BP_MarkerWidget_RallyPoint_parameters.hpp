#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_RallyPoint

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "UMG_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.ExecuteUbergraph_BP_MarkerWidget_RallyPoint
// 0x0060 (0x0060 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0014(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0050(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_ShouldMarkerUpdate_ReturnValue;           // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint) == 0x000060, "Wrong size on BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, EntryPoint) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, K2Node_Event_MyGeometry) == 0x000014, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, K2Node_Event_InDeltaTime) == 0x00004C, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000050, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint, CallFunc_ShouldMarkerUpdate_ReturnValue) == 0x000058, "Member 'BP_MarkerWidget_RallyPoint_C_ExecuteUbergraph_BP_MarkerWidget_RallyPoint::CallFunc_ShouldMarkerUpdate_ReturnValue' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.Tick
// 0x003C (0x003C - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_Tick) == 0x000004, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_Tick");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_Tick) == 0x00003C, "Wrong size on BP_MarkerWidget_RallyPoint_C_Tick");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_Tick, MyGeometry) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_Tick, InDeltaTime) == 0x000038, "Member 'BP_MarkerWidget_RallyPoint_C_Tick::InDeltaTime' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateSquadIDText
// 0x0030 (0x0030 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText final
{
public:
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSquadRallyPoint*                     K2Node_DynamicCast_AsSQSquad_Rally_Point;          // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30B8[0x6];                                     // 0x0012(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_IntToText_ReturnValue;               // 0x0018(0x0018)()
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText) == 0x000030, "Wrong size on BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText, CallFunc_GetOwner_ReturnValue) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText, K2Node_DynamicCast_AsSQSquad_Rally_Point) == 0x000008, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText::K2Node_DynamicCast_AsSQSquad_Rally_Point' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText, CallFunc_IsValid_ReturnValue) == 0x000011, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText, CallFunc_Conv_IntToText_ReturnValue) == 0x000018, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSquadIDText::CallFunc_Conv_IntToText_ReturnValue' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.OnMouseButtonDown
// 0x02D8 (0x02D8 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0160(0x00B8)()
	bool                                          CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue; // 0x0218(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30B9[0x7];                                     // 0x0219(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0220(0x00B8)()
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown) == 0x0002D8, "Wrong size on BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, MyGeometry) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::MyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, MouseEvent) == 0x000038, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::MouseEvent' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, ReturnValue) == 0x0000A8, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, CallFunc_Handled_ReturnValue) == 0x000160, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::CallFunc_Handled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue) == 0x000218, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown, CallFunc_Unhandled_ReturnValue) == 0x000220, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDown::CallFunc_Unhandled_ReturnValue' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateSelectVisibility
// 0x0038 (0x0038 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0001(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0002(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_30BA[0x5];                                     // 0x0003(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30BB[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQGameSpawn*                           CallFunc_GetSelectedSpawn_ReturnValue;             // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ObjectObject_ReturnValue;      // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility) == 0x000038, "Wrong size on BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, Temp_bool_Variable) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, Temp_byte_Variable) == 0x000001, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, Temp_byte_Variable_1) == 0x000002, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, CallFunc_GetOwner_ReturnValue) == 0x000010, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000018, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, CallFunc_GetSelectedSpawn_ReturnValue) == 0x000028, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::CallFunc_GetSelectedSpawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, CallFunc_EqualEqual_ObjectObject_ReturnValue) == 0x000030, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::CallFunc_EqualEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility, K2Node_Select_Default) == 0x000031, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateSelectVisibility::K2Node_Select_Default' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.SelectSpawn
// 0x0038 (0x0038 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_SelectSpawn final
{
public:
	bool                                          Commit;                                            // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30BC[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_PlayerController_C*                 K2Node_DynamicCast_AsBP_Player_Controller;         // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30BD[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSquadRallyPoint*                     K2Node_DynamicCast_AsSQSquad_Rally_Point;          // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0032(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_SelectSpawn) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_SelectSpawn");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_SelectSpawn) == 0x000038, "Wrong size on BP_MarkerWidget_RallyPoint_C_SelectSpawn");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, Commit) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::Commit' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, CallFunc_GetOwner_ReturnValue) == 0x000010, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, K2Node_DynamicCast_AsBP_Player_Controller) == 0x000018, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::K2Node_DynamicCast_AsBP_Player_Controller' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, K2Node_DynamicCast_AsSQSquad_Rally_Point) == 0x000028, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::K2Node_DynamicCast_AsSQSquad_Rally_Point' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, K2Node_DynamicCast_bSuccess_1) == 0x000030, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, CallFunc_IsValid_ReturnValue) == 0x000031, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_SelectSpawn, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000032, "Member 'BP_MarkerWidget_RallyPoint_C_SelectSpawn::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.OnMouseButtonDoubleClick
// 0x02E0 (0x02E0 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick final
{
public:
	struct FGeometry                              InMyGeometry;                                      // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          InMouseEvent;                                      // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	bool                                          CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue; // 0x0160(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30BE[0x7];                                     // 0x0161(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0168(0x00B8)()
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0220(0x00B8)()
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x02D8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick) == 0x0002E0, "Wrong size on BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, InMyGeometry) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::InMyGeometry' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, InMouseEvent) == 0x000038, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::InMouseEvent' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, ReturnValue) == 0x0000A8, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue) == 0x000160, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, CallFunc_Handled_ReturnValue) == 0x000168, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::CallFunc_Handled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, CallFunc_Unhandled_ReturnValue) == 0x000220, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::CallFunc_Unhandled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick, CallFunc_IsValid_ReturnValue) == 0x0002D8, "Member 'BP_MarkerWidget_RallyPoint_C_OnMouseButtonDoubleClick::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function BP_MarkerWidget_RallyPoint.BP_MarkerWidget_RallyPoint_C.UpdateRallyPointBrush
// 0x0140 (0x0140 - 0x0000)
struct BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush final
{
public:
	class AActor*                                 CallFunc_GetOwner_ReturnValue;                     // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush;                      // 0x0008(0x0088)()
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30BF[0x7];                                     // 0x0091(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSquadRallyPoint*                     K2Node_DynamicCast_AsSQSquad_Rally_Point;          // 0x0098(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30C0[0x7];                                     // 0x00A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x00B1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x00B2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_30C1[0x5];                                     // 0x00B3(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush_1;                    // 0x00B8(0x0088)()
};
static_assert(alignof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush) == 0x000008, "Wrong alignment on BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush");
static_assert(sizeof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush) == 0x000140, "Wrong size on BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_GetOwner_ReturnValue) == 0x000000, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_GetOwner_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, K2Node_MakeStruct_SlateBrush) == 0x000008, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::K2Node_MakeStruct_SlateBrush' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_IsValid_ReturnValue) == 0x000090, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, K2Node_DynamicCast_AsSQSquad_Rally_Point) == 0x000098, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::K2Node_DynamicCast_AsSQSquad_Rally_Point' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, K2Node_DynamicCast_bSuccess) == 0x0000A0, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_GetSquadPlayerController_Return_Value) == 0x0000A8, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_IsValid_ReturnValue_1) == 0x0000B0, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_IsValid_ReturnValue_2) == 0x0000B1, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x0000B2, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush, K2Node_MakeStruct_SlateBrush_1) == 0x0000B8, "Member 'BP_MarkerWidget_RallyPoint_C_UpdateRallyPointBrush::K2Node_MakeStruct_SlateBrush_1' has a wrong offset!");

}

