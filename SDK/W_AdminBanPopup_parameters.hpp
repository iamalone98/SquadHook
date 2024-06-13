#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_AdminBanPopup

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_AdminBanPopup.W_AdminBanPopup_C.OnExecuteBan__DelegateSignature
// 0x0030 (0x0030 - 0x0000)
struct W_AdminBanPopup_C_OnExecuteBan__DelegateSignature final
{
public:
	class FText                                   Reason;                                            // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
	class FText                                   Time;                                              // 0x0018(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm)
};
static_assert(alignof(W_AdminBanPopup_C_OnExecuteBan__DelegateSignature) == 0x000008, "Wrong alignment on W_AdminBanPopup_C_OnExecuteBan__DelegateSignature");
static_assert(sizeof(W_AdminBanPopup_C_OnExecuteBan__DelegateSignature) == 0x000030, "Wrong size on W_AdminBanPopup_C_OnExecuteBan__DelegateSignature");
static_assert(offsetof(W_AdminBanPopup_C_OnExecuteBan__DelegateSignature, Reason) == 0x000000, "Member 'W_AdminBanPopup_C_OnExecuteBan__DelegateSignature::Reason' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_OnExecuteBan__DelegateSignature, Time) == 0x000018, "Member 'W_AdminBanPopup_C_OnExecuteBan__DelegateSignature::Time' has a wrong offset!");

// Function W_AdminBanPopup.W_AdminBanPopup_C.ExecuteUbergraph_W_AdminBanPopup
// 0x0098 (0x0098 - 0x0000)
struct W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FE5[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetText_ReturnValue;                      // 0x0008(0x0018)()
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0020(0x0010)(ZeroConstructor, NoDestructor)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0030(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0068(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FE6[0x4];                                     // 0x006C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_GetText_ReturnValue_1;                    // 0x0070(0x0018)()
	bool                                          CallFunc_IsHovered_ReturnValue;                    // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_IsTimerActiveHandle_ReturnValue;       // 0x0089(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x008A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FE7[0x5];                                     // 0x008B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0090(0x0008)(NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup) == 0x000008, "Wrong alignment on W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup");
static_assert(sizeof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup) == 0x000098, "Wrong size on W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, EntryPoint) == 0x000000, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_GetText_ReturnValue) == 0x000008, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_GetText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, K2Node_CreateDelegate_OutputDelegate) == 0x000020, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, K2Node_Event_MyGeometry) == 0x000030, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, K2Node_Event_InDeltaTime) == 0x000068, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_GetText_ReturnValue_1) == 0x000070, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_GetText_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_IsHovered_ReturnValue) == 0x000088, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_IsHovered_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_K2_IsTimerActiveHandle_ReturnValue) == 0x000089, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_K2_IsTimerActiveHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_Not_PreBool_ReturnValue) == 0x00008A, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000090, "Member 'W_AdminBanPopup_C_ExecuteUbergraph_W_AdminBanPopup::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");

// Function W_AdminBanPopup.W_AdminBanPopup_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_AdminBanPopup_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_AdminBanPopup_C_Tick) == 0x000004, "Wrong alignment on W_AdminBanPopup_C_Tick");
static_assert(sizeof(W_AdminBanPopup_C_Tick) == 0x00003C, "Wrong size on W_AdminBanPopup_C_Tick");
static_assert(offsetof(W_AdminBanPopup_C_Tick, MyGeometry) == 0x000000, "Member 'W_AdminBanPopup_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Tick, InDeltaTime) == 0x000038, "Member 'W_AdminBanPopup_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_AdminBanPopup.W_AdminBanPopup_C.Get_PlayerName
// 0x0080 (0x0080 - 0x0000)
struct W_AdminBanPopup_C_Get_PlayerName final
{
public:
	class FText                                   ReturnValue;                                       // 0x0000(0x0018)(Parm, OutParm, ReturnParm)
	bool                                          Temp_bool_Variable;                                // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FE8[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_TextToString_ReturnValue;            // 0x0020(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	int32                                         CallFunc_Len_ReturnValue;                          // 0x0030(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FE9[0x4];                                     // 0x0034(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_LeftChop_ReturnValue;                     // 0x0038(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FEA[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0050(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0068(0x0018)()
};
static_assert(alignof(W_AdminBanPopup_C_Get_PlayerName) == 0x000008, "Wrong alignment on W_AdminBanPopup_C_Get_PlayerName");
static_assert(sizeof(W_AdminBanPopup_C_Get_PlayerName) == 0x000080, "Wrong size on W_AdminBanPopup_C_Get_PlayerName");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, ReturnValue) == 0x000000, "Member 'W_AdminBanPopup_C_Get_PlayerName::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, Temp_bool_Variable) == 0x000018, "Member 'W_AdminBanPopup_C_Get_PlayerName::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, CallFunc_Conv_TextToString_ReturnValue) == 0x000020, "Member 'W_AdminBanPopup_C_Get_PlayerName::CallFunc_Conv_TextToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, CallFunc_Len_ReturnValue) == 0x000030, "Member 'W_AdminBanPopup_C_Get_PlayerName::CallFunc_Len_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, CallFunc_LeftChop_ReturnValue) == 0x000038, "Member 'W_AdminBanPopup_C_Get_PlayerName::CallFunc_LeftChop_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, CallFunc_Greater_IntInt_ReturnValue) == 0x000048, "Member 'W_AdminBanPopup_C_Get_PlayerName::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, CallFunc_Conv_StringToText_ReturnValue) == 0x000050, "Member 'W_AdminBanPopup_C_Get_PlayerName::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_AdminBanPopup_C_Get_PlayerName, K2Node_Select_Default) == 0x000068, "Member 'W_AdminBanPopup_C_Get_PlayerName::K2Node_Select_Default' has a wrong offset!");

}

