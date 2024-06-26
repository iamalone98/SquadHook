#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_TrashPlayer

#include "Basic.hpp"

#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_TrashPlayer.W_TrashPlayer_C.ExecuteUbergraph_W_TrashPlayer
// 0x0130 (0x0130 - 0x0000)
struct W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4288[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FPointerEvent                          K2Node_Event_PointerEvent_1;                       // 0x0008(0x0070)()
	class UDragDropOperation*                     K2Node_Event_Operation_1;                          // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0080(0x0038)(IsPlainOldData, NoDestructor)
	struct FPointerEvent                          K2Node_Event_PointerEvent;                         // 0x00B8(0x0070)()
	class UDragDropOperation*                     K2Node_Event_Operation;                            // 0x0128(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer) == 0x000008, "Wrong alignment on W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer");
static_assert(sizeof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer) == 0x000130, "Wrong size on W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, EntryPoint) == 0x000000, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, K2Node_Event_PointerEvent_1) == 0x000008, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::K2Node_Event_PointerEvent_1' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, K2Node_Event_Operation_1) == 0x000078, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::K2Node_Event_Operation_1' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, K2Node_Event_MyGeometry) == 0x000080, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, K2Node_Event_PointerEvent) == 0x0000B8, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::K2Node_Event_PointerEvent' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer, K2Node_Event_Operation) == 0x000128, "Member 'W_TrashPlayer_C_ExecuteUbergraph_W_TrashPlayer::K2Node_Event_Operation' has a wrong offset!");

// Function W_TrashPlayer.W_TrashPlayer_C.OnDragEnter
// 0x00B0 (0x00B0 - 0x0000)
struct W_TrashPlayer_C_OnDragEnter final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          PointerEvent;                                      // 0x0038(0x0070)(BlueprintVisible, BlueprintReadOnly, Parm)
	class UDragDropOperation*                     Operation;                                         // 0x00A8(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_TrashPlayer_C_OnDragEnter) == 0x000008, "Wrong alignment on W_TrashPlayer_C_OnDragEnter");
static_assert(sizeof(W_TrashPlayer_C_OnDragEnter) == 0x0000B0, "Wrong size on W_TrashPlayer_C_OnDragEnter");
static_assert(offsetof(W_TrashPlayer_C_OnDragEnter, MyGeometry) == 0x000000, "Member 'W_TrashPlayer_C_OnDragEnter::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDragEnter, PointerEvent) == 0x000038, "Member 'W_TrashPlayer_C_OnDragEnter::PointerEvent' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDragEnter, Operation) == 0x0000A8, "Member 'W_TrashPlayer_C_OnDragEnter::Operation' has a wrong offset!");

// Function W_TrashPlayer.W_TrashPlayer_C.OnDragLeave
// 0x0078 (0x0078 - 0x0000)
struct W_TrashPlayer_C_OnDragLeave final
{
public:
	struct FPointerEvent                          PointerEvent;                                      // 0x0000(0x0070)(BlueprintVisible, BlueprintReadOnly, Parm)
	class UDragDropOperation*                     Operation;                                         // 0x0070(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_TrashPlayer_C_OnDragLeave) == 0x000008, "Wrong alignment on W_TrashPlayer_C_OnDragLeave");
static_assert(sizeof(W_TrashPlayer_C_OnDragLeave) == 0x000078, "Wrong size on W_TrashPlayer_C_OnDragLeave");
static_assert(offsetof(W_TrashPlayer_C_OnDragLeave, PointerEvent) == 0x000000, "Member 'W_TrashPlayer_C_OnDragLeave::PointerEvent' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDragLeave, Operation) == 0x000070, "Member 'W_TrashPlayer_C_OnDragLeave::Operation' has a wrong offset!");

// Function W_TrashPlayer.W_TrashPlayer_C.OnDrop
// 0x00E0 (0x00E0 - 0x0000)
struct W_TrashPlayer_C_OnDrop final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          PointerEvent;                                      // 0x0038(0x0070)(BlueprintVisible, BlueprintReadOnly, Parm)
	class UDragDropOperation*                     Operation;                                         // 0x00A8(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x00B0(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4289[0x7];                                     // 0x00B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_428A[0x7];                                     // 0x00C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SquadMemberItem_C*                   K2Node_DynamicCast_AsW_Squad_Member_Item;          // 0x00D0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x00D8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_TrashPlayer_C_OnDrop) == 0x000008, "Wrong alignment on W_TrashPlayer_C_OnDrop");
static_assert(sizeof(W_TrashPlayer_C_OnDrop) == 0x0000E0, "Wrong size on W_TrashPlayer_C_OnDrop");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, MyGeometry) == 0x000000, "Member 'W_TrashPlayer_C_OnDrop::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, PointerEvent) == 0x000038, "Member 'W_TrashPlayer_C_OnDrop::PointerEvent' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, Operation) == 0x0000A8, "Member 'W_TrashPlayer_C_OnDrop::Operation' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, ReturnValue) == 0x0000B0, "Member 'W_TrashPlayer_C_OnDrop::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, CallFunc_GetOwningPlayer_ReturnValue) == 0x0000B8, "Member 'W_TrashPlayer_C_OnDrop::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x0000C0, "Member 'W_TrashPlayer_C_OnDrop::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, K2Node_DynamicCast_bSuccess) == 0x0000C8, "Member 'W_TrashPlayer_C_OnDrop::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, K2Node_DynamicCast_AsW_Squad_Member_Item) == 0x0000D0, "Member 'W_TrashPlayer_C_OnDrop::K2Node_DynamicCast_AsW_Squad_Member_Item' has a wrong offset!");
static_assert(offsetof(W_TrashPlayer_C_OnDrop, K2Node_DynamicCast_bSuccess_1) == 0x0000D8, "Member 'W_TrashPlayer_C_OnDrop::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");

}

