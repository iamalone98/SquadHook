#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: WBP_SetHeliLockFreeLook

#include "Basic.hpp"


namespace SDK::Params
{

// Function WBP_SetHeliLockFreeLook.WBP_SetHeliLockFreeLook_C.ExecuteUbergraph_WBP_SetHeliLockFreeLook
// 0x0018 (0x0018 - 0x0000)
struct WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_ComponentBoundEvent_bIsChecked;             // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_318A[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue;     // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue_1;   // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook) == 0x000008, "Wrong alignment on WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook");
static_assert(sizeof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook) == 0x000018, "Wrong size on WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook");
static_assert(offsetof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook, EntryPoint) == 0x000000, "Member 'WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook::EntryPoint' has a wrong offset!");
static_assert(offsetof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook, K2Node_ComponentBoundEvent_bIsChecked) == 0x000004, "Member 'WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook::K2Node_ComponentBoundEvent_bIsChecked' has a wrong offset!");
static_assert(offsetof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook, CallFunc_GetSquadGameUserSettings_ReturnValue) == 0x000008, "Member 'WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook::CallFunc_GetSquadGameUserSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook, CallFunc_GetSquadGameUserSettings_ReturnValue_1) == 0x000010, "Member 'WBP_SetHeliLockFreeLook_C_ExecuteUbergraph_WBP_SetHeliLockFreeLook::CallFunc_GetSquadGameUserSettings_ReturnValue_1' has a wrong offset!");

// Function WBP_SetHeliLockFreeLook.WBP_SetHeliLockFreeLook_C.BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature
// 0x0001 (0x0001 - 0x0000)
struct WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature final
{
public:
	bool                                          bIsChecked;                                        // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature) == 0x000001, "Wrong alignment on WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature");
static_assert(sizeof(WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature) == 0x000001, "Wrong size on WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature");
static_assert(offsetof(WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature, bIsChecked) == 0x000000, "Member 'WBP_SetHeliLockFreeLook_C_BndEvt__AlwaysFreeLookBox_K2Node_ComponentBoundEvent_0_OnCheckBoxComponentStateChanged__DelegateSignature::bIsChecked' has a wrong offset!");

}

