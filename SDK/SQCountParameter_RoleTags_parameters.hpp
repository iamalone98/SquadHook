#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQCountParameter_RoleTags

#include "Basic.hpp"

#include "SQRoleTags_structs.hpp"


namespace SDK::Params
{

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetCountedTaggedRole
// 0x0068 (0x0068 - 0x0000)
struct SQCountParameter_RoleTags_C_GetCountedTaggedRole final
{
public:
	class ASQPlayerState*                         In_PlayerState;                                    // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Out_Counted;                                       // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         L_Result;                                          // 0x000C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<ESQRoleTags>                           L_TagArray;                                        // 0x0010(0x0010)(Edit, BlueprintVisible)
	int32                                         Temp_int_Variable;                                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0025(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA0[0x2];                                     // 0x0026(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x0031(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA1[0x6];                                     // 0x0032(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings_1;         // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA2[0x3];                                     // 0x0041(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Variable_1;                               // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasTags_Out_Has_Tags;                     // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA3[0x3];                                     // 0x004D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasTags_Out_Has_Tags_1;                   // 0x0054(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA4[0x3];                                     // 0x0055(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<ESQRoleTags>                           CallFunc_Set_ToArray_Result;                       // 0x0058(0x0010)(ReferenceParm)
};
static_assert(alignof(SQCountParameter_RoleTags_C_GetCountedTaggedRole) == 0x000008, "Wrong alignment on SQCountParameter_RoleTags_C_GetCountedTaggedRole");
static_assert(sizeof(SQCountParameter_RoleTags_C_GetCountedTaggedRole) == 0x000068, "Wrong size on SQCountParameter_RoleTags_C_GetCountedTaggedRole");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, In_PlayerState) == 0x000000, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::In_PlayerState' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, Out_Counted) == 0x000008, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::Out_Counted' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, L_Result) == 0x00000C, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::L_Result' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, L_TagArray) == 0x000010, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::L_TagArray' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, Temp_int_Variable) == 0x000020, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_IsValid_ReturnValue) == 0x000024, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_IsValid_ReturnValue_1) == 0x000025, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x000028, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, K2Node_DynamicCast_bSuccess) == 0x000030, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x000031, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, K2Node_DynamicCast_AsBP_SQRole_Settings_1) == 0x000038, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::K2Node_DynamicCast_AsBP_SQRole_Settings_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, Temp_int_Variable_1) == 0x000044, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::Temp_int_Variable_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_Add_IntInt_ReturnValue) == 0x000048, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_HasTags_Out_Has_Tags) == 0x00004C, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_HasTags_Out_Has_Tags' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_Add_IntInt_ReturnValue_1) == 0x000050, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_HasTags_Out_Has_Tags_1) == 0x000054, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_HasTags_Out_Has_Tags_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetCountedTaggedRole, CallFunc_Set_ToArray_Result) == 0x000058, "Member 'SQCountParameter_RoleTags_C_GetCountedTaggedRole::CallFunc_Set_ToArray_Result' has a wrong offset!");

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.TryGetValueForTeam
// 0x0050 (0x0050 - 0x0000)
struct SQCountParameter_RoleTags_C_TryGetValueForTeam final
{
public:
	const class ASQTeam*                          InTeam;                                            // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         OutValue;                                          // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x000C(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA5[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         L_Used;                                            // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA6[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetMaxCountForTeamsize_Out_Count;         // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_1CA7[0x4];                                     // 0x002C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         CallFunc_Array_Get_Item;                           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetCountedTaggedRole_Out_Counted;         // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x003C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA8[0x3];                                     // 0x003D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0045(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CA9[0x2];                                     // 0x0046(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         K2Node_Select_Default;                             // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SQCountParameter_RoleTags_C_TryGetValueForTeam) == 0x000008, "Wrong alignment on SQCountParameter_RoleTags_C_TryGetValueForTeam");
static_assert(sizeof(SQCountParameter_RoleTags_C_TryGetValueForTeam) == 0x000050, "Wrong size on SQCountParameter_RoleTags_C_TryGetValueForTeam");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, InTeam) == 0x000000, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::InTeam' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, OutValue) == 0x000008, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::OutValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, ReturnValue) == 0x00000C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, L_Used) == 0x000010, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::L_Used' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, Temp_int_Variable) == 0x000014, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_IsValid_ReturnValue) == 0x000018, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Array_Length_ReturnValue) == 0x00001C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_GetMaxCountForTeamsize_Out_Count) == 0x000020, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_GetMaxCountForTeamsize_Out_Count' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, Temp_int_Array_Index_Variable) == 0x000024, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, Temp_int_Loop_Counter_Variable) == 0x000028, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Array_Get_Item) == 0x000030, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_GetCountedTaggedRole_Out_Counted) == 0x000038, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_GetCountedTaggedRole_Out_Counted' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Less_IntInt_ReturnValue) == 0x00003C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Add_IntInt_ReturnValue) == 0x000040, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, Temp_bool_Variable) == 0x000044, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Less_IntInt_ReturnValue_1) == 0x000045, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, CallFunc_Add_IntInt_ReturnValue_1) == 0x000048, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForTeam, K2Node_Select_Default) == 0x00004C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForTeam::K2Node_Select_Default' has a wrong offset!");

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.TryGetValueForPlayer
// 0x0058 (0x0058 - 0x0000)
struct SQCountParameter_RoleTags_C_TryGetValueForPlayer final
{
public:
	const class ASQPlayerController*              InPlayer;                                          // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         OutValue;                                          // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x000C(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CAA[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         L_Used;                                            // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CAB[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetMaxCountForSquadSize_Out_Count;        // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_1CAC[0x4];                                     // 0x002C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         CallFunc_Array_Get_Item;                           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CAD[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetCountedTaggedRole_Out_Counted;         // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CAE[0x3];                                     // 0x0041(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CAF[0x3];                                     // 0x0049(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x004C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CB0[0x3];                                     // 0x0051(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         K2Node_Select_Default;                             // 0x0054(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SQCountParameter_RoleTags_C_TryGetValueForPlayer) == 0x000008, "Wrong alignment on SQCountParameter_RoleTags_C_TryGetValueForPlayer");
static_assert(sizeof(SQCountParameter_RoleTags_C_TryGetValueForPlayer) == 0x000058, "Wrong size on SQCountParameter_RoleTags_C_TryGetValueForPlayer");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, InPlayer) == 0x000000, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::InPlayer' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, OutValue) == 0x000008, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::OutValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, ReturnValue) == 0x00000C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, L_Used) == 0x000010, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::L_Used' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, Temp_int_Variable) == 0x000014, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_IsValid_ReturnValue) == 0x000018, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Array_Length_ReturnValue) == 0x00001C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_GetMaxCountForSquadSize_Out_Count) == 0x000020, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_GetMaxCountForSquadSize_Out_Count' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, Temp_int_Array_Index_Variable) == 0x000024, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, Temp_int_Loop_Counter_Variable) == 0x000028, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Array_Get_Item) == 0x000030, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x000038, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_GetCountedTaggedRole_Out_Counted) == 0x00003C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_GetCountedTaggedRole_Out_Counted' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Less_IntInt_ReturnValue) == 0x000040, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Add_IntInt_ReturnValue) == 0x000044, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, Temp_bool_Variable) == 0x000048, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Add_IntInt_ReturnValue_1) == 0x00004C, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, CallFunc_Less_IntInt_ReturnValue_1) == 0x000050, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_TryGetValueForPlayer, K2Node_Select_Default) == 0x000054, "Member 'SQCountParameter_RoleTags_C_TryGetValueForPlayer::K2Node_Select_Default' has a wrong offset!");

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetMaxCountForTeamsize
// 0x0020 (0x0020 - 0x0000)
struct SQCountParameter_RoleTags_C_GetMaxCountForTeamsize final
{
public:
	class ASQTeam*                                In_Team;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Out_Count;                                         // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetPlayerCount_ReturnValue;               // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetFloatValue_ReturnValue;                // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_FTrunc_ReturnValue;                       // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize) == 0x000008, "Wrong alignment on SQCountParameter_RoleTags_C_GetMaxCountForTeamsize");
static_assert(sizeof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize) == 0x000020, "Wrong size on SQCountParameter_RoleTags_C_GetMaxCountForTeamsize");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, In_Team) == 0x000000, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::In_Team' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, Out_Count) == 0x000008, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::Out_Count' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, CallFunc_GetPlayerCount_ReturnValue) == 0x00000C, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::CallFunc_GetPlayerCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, CallFunc_Conv_IntToFloat_ReturnValue) == 0x000010, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, CallFunc_GetFloatValue_ReturnValue) == 0x000014, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::CallFunc_GetFloatValue_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForTeamsize, CallFunc_FTrunc_ReturnValue) == 0x000018, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForTeamsize::CallFunc_FTrunc_ReturnValue' has a wrong offset!");

// Function SQCountParameter_RoleTags.SQCountParameter_RoleTags_C.GetMaxCountForSquadSize
// 0x0020 (0x0020 - 0x0000)
struct SQCountParameter_RoleTags_C_GetMaxCountForSquadSize final
{
public:
	class ASQPlayerController*                    In_Player;                                         // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Out_Count;                                         // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_1CB1[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetPlayerCount_ReturnValue;               // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetFloatValue_ReturnValue;                // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_FTrunc_ReturnValue;                       // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize) == 0x000008, "Wrong alignment on SQCountParameter_RoleTags_C_GetMaxCountForSquadSize");
static_assert(sizeof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize) == 0x000020, "Wrong size on SQCountParameter_RoleTags_C_GetMaxCountForSquadSize");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, In_Player) == 0x000000, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::In_Player' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, Out_Count) == 0x000008, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::Out_Count' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, CallFunc_IsValid_ReturnValue) == 0x00000C, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, CallFunc_GetPlayerCount_ReturnValue) == 0x000010, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::CallFunc_GetPlayerCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, CallFunc_Conv_IntToFloat_ReturnValue) == 0x000014, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, CallFunc_GetFloatValue_ReturnValue) == 0x000018, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::CallFunc_GetFloatValue_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_RoleTags_C_GetMaxCountForSquadSize, CallFunc_FTrunc_ReturnValue) == 0x00001C, "Member 'SQCountParameter_RoleTags_C_GetMaxCountForSquadSize::CallFunc_FTrunc_ReturnValue' has a wrong offset!");

}
