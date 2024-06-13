#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_GridHeader_FTL_Orders

#include "Basic.hpp"


namespace SDK::Params
{

// Function W_GridHeader_FTL_Orders.W_GridHeader_FTL_Orders_C.Get Fireteam ID
// 0x0020 (0x0020 - 0x0000)
struct W_GridHeader_FTL_Orders_C_Get_Fireteam_ID final
{
public:
	int32                                         ID;                                                // 0x0000(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4523[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4524[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetFireTeamIndex_ReturnValue;             // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID) == 0x000008, "Wrong alignment on W_GridHeader_FTL_Orders_C_Get_Fireteam_ID");
static_assert(sizeof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID) == 0x000020, "Wrong size on W_GridHeader_FTL_Orders_C_Get_Fireteam_ID");
static_assert(offsetof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID, ID) == 0x000000, "Member 'W_GridHeader_FTL_Orders_C_Get_Fireteam_ID::ID' has a wrong offset!");
static_assert(offsetof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_GridHeader_FTL_Orders_C_Get_Fireteam_ID::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID, K2Node_DynamicCast_AsSQPlayer_State) == 0x000010, "Member 'W_GridHeader_FTL_Orders_C_Get_Fireteam_ID::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'W_GridHeader_FTL_Orders_C_Get_Fireteam_ID::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_GridHeader_FTL_Orders_C_Get_Fireteam_ID, CallFunc_GetFireTeamIndex_ReturnValue) == 0x00001C, "Member 'W_GridHeader_FTL_Orders_C_Get_Fireteam_ID::CallFunc_GetFireTeamIndex_ReturnValue' has a wrong offset!");

}

