#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQCountParameter_TeamMate

#include "Basic.hpp"


namespace SDK::Params
{

// Function SQCountParameter_TeamMate.SQCountParameter_TeamMate_C.TryGetInputValueForTeam
// 0x0018 (0x0018 - 0x0000)
struct SQCountParameter_TeamMate_C_TryGetInputValueForTeam final
{
public:
	const class ASQTeam*                          InTeam;                                            // 0x0000(0x0008)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OutValue;                                          // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReturnValue;                                       // 0x000C(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BC1[0x3];                                     // 0x000D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetPlayerCount_ReturnValue;               // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Conv_IntToFloat_ReturnValue;              // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam) == 0x000008, "Wrong alignment on SQCountParameter_TeamMate_C_TryGetInputValueForTeam");
static_assert(sizeof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam) == 0x000018, "Wrong size on SQCountParameter_TeamMate_C_TryGetInputValueForTeam");
static_assert(offsetof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam, InTeam) == 0x000000, "Member 'SQCountParameter_TeamMate_C_TryGetInputValueForTeam::InTeam' has a wrong offset!");
static_assert(offsetof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam, OutValue) == 0x000008, "Member 'SQCountParameter_TeamMate_C_TryGetInputValueForTeam::OutValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam, ReturnValue) == 0x00000C, "Member 'SQCountParameter_TeamMate_C_TryGetInputValueForTeam::ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam, CallFunc_GetPlayerCount_ReturnValue) == 0x000010, "Member 'SQCountParameter_TeamMate_C_TryGetInputValueForTeam::CallFunc_GetPlayerCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(SQCountParameter_TeamMate_C_TryGetInputValueForTeam, CallFunc_Conv_IntToFloat_ReturnValue) == 0x000014, "Member 'SQCountParameter_TeamMate_C_TryGetInputValueForTeam::CallFunc_Conv_IntToFloat_ReturnValue' has a wrong offset!");

}

