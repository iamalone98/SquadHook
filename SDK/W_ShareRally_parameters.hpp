#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ShareRally

#include "Basic.hpp"


namespace SDK::Params
{

// Function W_ShareRally.W_ShareRally_C.ExecuteUbergraph_W_ShareRally
// 0x0020 (0x0020 - 0x0000)
struct W_ShareRally_C_ExecuteUbergraph_W_ShareRally final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_31C1[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally) == 0x000008, "Wrong alignment on W_ShareRally_C_ExecuteUbergraph_W_ShareRally");
static_assert(sizeof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally) == 0x000020, "Wrong size on W_ShareRally_C_ExecuteUbergraph_W_ShareRally");
static_assert(offsetof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally, EntryPoint) == 0x000000, "Member 'W_ShareRally_C_ExecuteUbergraph_W_ShareRally::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_ShareRally_C_ExecuteUbergraph_W_ShareRally::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000010, "Member 'W_ShareRally_C_ExecuteUbergraph_W_ShareRally::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_ShareRally_C_ExecuteUbergraph_W_ShareRally, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'W_ShareRally_C_ExecuteUbergraph_W_ShareRally::K2Node_DynamicCast_bSuccess' has a wrong offset!");

}

