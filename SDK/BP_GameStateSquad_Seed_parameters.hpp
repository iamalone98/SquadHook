#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GameStateSquad_Seed

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_GameStateSquad_Seed.BP_GameStateSquad_Seed_C.OnCountdownStateChanged__DelegateSignature
// 0x0008 (0x0008 - 0x0000)
struct BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature final
{
public:
	bool                                          bIsActive;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35F2[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         TimeLeft;                                          // 0x0004(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature) == 0x000004, "Wrong alignment on BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature");
static_assert(sizeof(BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature) == 0x000008, "Wrong size on BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature, bIsActive) == 0x000000, "Member 'BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature::bIsActive' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature, TimeLeft) == 0x000004, "Member 'BP_GameStateSquad_Seed_C_OnCountdownStateChanged__DelegateSignature::TimeLeft' has a wrong offset!");

// Function BP_GameStateSquad_Seed.BP_GameStateSquad_Seed_C.OnRep_bGameIsLive
// 0x00B8 (0x00B8 - 0x0000)
struct BP_GameStateSquad_Seed_C_OnRep_bGameIsLive final
{
public:
	bool                                          Temp_bool_Variable;                                // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35F3[0x7];                                     // 0x0001(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	class FText                                   Temp_text_Variable_1;                              // 0x0020(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0038(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0050(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0090(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00A0(0x0018)()
};
static_assert(alignof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive) == 0x000008, "Wrong alignment on BP_GameStateSquad_Seed_C_OnRep_bGameIsLive");
static_assert(sizeof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive) == 0x0000B8, "Wrong size on BP_GameStateSquad_Seed_C_OnRep_bGameIsLive");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, Temp_bool_Variable) == 0x000000, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, Temp_text_Variable) == 0x000008, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, Temp_text_Variable_1) == 0x000020, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::Temp_text_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, K2Node_Select_Default) == 0x000038, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, K2Node_MakeStruct_FormatArgumentData) == 0x000050, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, K2Node_MakeArray_Array) == 0x000090, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_bGameIsLive, CallFunc_Format_ReturnValue) == 0x0000A0, "Member 'BP_GameStateSquad_Seed_C_OnRep_bGameIsLive::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function BP_GameStateSquad_Seed.BP_GameStateSquad_Seed_C.OnRep_ServerTimeToFinishCountdown
// 0x0120 (0x0120 - 0x0000)
struct BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown final
{
public:
	float                                         TimeLeft;                                          // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bOldCountdownActive;                               // 0x0004(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Variable;                                // 0x0005(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35F4[0x2];                                     // 0x0006(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0008(0x0018)()
	bool                                          Temp_bool_Variable_1;                              // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35F5[0x3];                                     // 0x0021(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Temp_float_Variable;                               // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0028(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x0068(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x0078(0x0018)()
	class FText                                   K2Node_Select_Default;                             // 0x0090(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData_1;            // 0x00A8(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array_1;                          // 0x00E8(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue_1;                     // 0x00F8(0x0018)()
	float                                         CallFunc_GetServerWorldTimeSeconds_ReturnValue;    // 0x0110(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0114(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Select_Default_1;                           // 0x0118(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_BoolBool_ReturnValue;            // 0x011C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_FloatFloat_ReturnValue;          // 0x011D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown) == 0x000008, "Wrong alignment on BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown");
static_assert(sizeof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown) == 0x000120, "Wrong size on BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, TimeLeft) == 0x000000, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::TimeLeft' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, bOldCountdownActive) == 0x000004, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::bOldCountdownActive' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, Temp_bool_Variable) == 0x000005, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, Temp_text_Variable) == 0x000008, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, Temp_bool_Variable_1) == 0x000020, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::Temp_bool_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, Temp_float_Variable) == 0x000024, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::Temp_float_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_MakeStruct_FormatArgumentData) == 0x000028, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_MakeArray_Array) == 0x000068, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_Format_ReturnValue) == 0x000078, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_Format_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_Select_Default) == 0x000090, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_MakeStruct_FormatArgumentData_1) == 0x0000A8, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_MakeStruct_FormatArgumentData_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_MakeArray_Array_1) == 0x0000E8, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_MakeArray_Array_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_Format_ReturnValue_1) == 0x0000F8, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_Format_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_GetServerWorldTimeSeconds_ReturnValue) == 0x000110, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_GetServerWorldTimeSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000114, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, K2Node_Select_Default_1) == 0x000118, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::K2Node_Select_Default_1' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_NotEqual_BoolBool_ReturnValue) == 0x00011C, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_NotEqual_BoolBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown, CallFunc_NotEqual_FloatFloat_ReturnValue) == 0x00011D, "Member 'BP_GameStateSquad_Seed_C_OnRep_ServerTimeToFinishCountdown::CallFunc_NotEqual_FloatFloat_ReturnValue' has a wrong offset!");

// Function BP_GameStateSquad_Seed.BP_GameStateSquad_Seed_C.GetPlayerCountOnServer
// 0x0008 (0x0008 - 0x0000)
struct BP_GameStateSquad_Seed_C_GetPlayerCountOnServer final
{
public:
	int32                                         ReturnValue;                                       // 0x0000(0x0004)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GameStateSquad_Seed_C_GetPlayerCountOnServer) == 0x000004, "Wrong alignment on BP_GameStateSquad_Seed_C_GetPlayerCountOnServer");
static_assert(sizeof(BP_GameStateSquad_Seed_C_GetPlayerCountOnServer) == 0x000008, "Wrong size on BP_GameStateSquad_Seed_C_GetPlayerCountOnServer");
static_assert(offsetof(BP_GameStateSquad_Seed_C_GetPlayerCountOnServer, ReturnValue) == 0x000000, "Member 'BP_GameStateSquad_Seed_C_GetPlayerCountOnServer::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameStateSquad_Seed_C_GetPlayerCountOnServer, CallFunc_Array_Length_ReturnValue) == 0x000004, "Member 'BP_GameStateSquad_Seed_C_GetPlayerCountOnServer::CallFunc_Array_Length_ReturnValue' has a wrong offset!");

}
