#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQMapActionSettings

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BP_SQMapActionSettings.BP_SQMapActionSettings_C.GetMapActionActiveTime
// 0x00A8 (0x00A8 - 0x0000)
struct BP_SQMapActionSettings_C_GetMapActionActiveTime final
{
public:
	class ASQPlayerController*                    InPlayer;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ActiveTime;                                        // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ActiveTimePercent;                                 // 0x000C(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Cooldown;                                          // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F26[0x4];                                     // 0x001C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Action            CallFunc_TryGetActionAvailability_OutUpdatedActionState; // 0x0020(0x0050)(ContainsInstancedReference)
	bool                                          CallFunc_TryGetActionAvailability_ReturnValue;     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasDelay_ReturnValue;                     // 0x0071(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F27[0x6];                                     // 0x0072(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRestriction_Delay*                   K2Node_DynamicCast_AsSQRestriction_Delay;          // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F28[0x7];                                     // 0x0081(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimespan                              CallFunc_GetAvailabilityDelay_ReturnValue;         // 0x0088(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue;              // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue_1;            // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_1;        // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue;      // 0x00A4(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue_1;    // 0x00A5(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQMapActionSettings_C_GetMapActionActiveTime) == 0x000008, "Wrong alignment on BP_SQMapActionSettings_C_GetMapActionActiveTime");
static_assert(sizeof(BP_SQMapActionSettings_C_GetMapActionActiveTime) == 0x0000A8, "Wrong size on BP_SQMapActionSettings_C_GetMapActionActiveTime");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, InPlayer) == 0x000000, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::InPlayer' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, ActiveTime) == 0x000008, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::ActiveTime' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, ActiveTimePercent) == 0x00000C, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::ActiveTimePercent' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, Cooldown) == 0x000010, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::Cooldown' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_Add_FloatFloat_ReturnValue) == 0x000014, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x000018, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_TryGetActionAvailability_OutUpdatedActionState) == 0x000020, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_TryGetActionAvailability_OutUpdatedActionState' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_TryGetActionAvailability_ReturnValue) == 0x000070, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_TryGetActionAvailability_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_HasDelay_ReturnValue) == 0x000071, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_HasDelay_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, K2Node_DynamicCast_AsSQRestriction_Delay) == 0x000078, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::K2Node_DynamicCast_AsSQRestriction_Delay' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, K2Node_DynamicCast_bSuccess) == 0x000080, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_GetAvailabilityDelay_ReturnValue) == 0x000088, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_GetAvailabilityDelay_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_GetTotalSeconds_ReturnValue) == 0x000090, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_GetTotalSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_GetTotalSeconds_ReturnValue_1) == 0x000094, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_GetTotalSeconds_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000098, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_Subtract_FloatFloat_ReturnValue_1) == 0x00009C, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_Subtract_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000A0, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_GreaterEqual_FloatFloat_ReturnValue) == 0x0000A4, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_GreaterEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionActiveTime, CallFunc_GreaterEqual_FloatFloat_ReturnValue_1) == 0x0000A5, "Member 'BP_SQMapActionSettings_C_GetMapActionActiveTime::CallFunc_GreaterEqual_FloatFloat_ReturnValue_1' has a wrong offset!");

// Function BP_SQMapActionSettings.BP_SQMapActionSettings_C.GetMapActionState
// 0x0098 (0x0098 - 0x0000)
struct BP_SQMapActionSettings_C_GetMapActionState final
{
public:
	class ASQPlayerController*                    InPlayer;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQCommandOptionState                         ActionState;                                       // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F29[0x3];                                     // 0x0009(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Cooldown;                                          // 0x000C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQAvailabilityState_Action            CallFunc_TryGetActionAvailability_OutUpdatedActionState; // 0x0018(0x0050)(ContainsInstancedReference)
	bool                                          CallFunc_TryGetActionAvailability_ReturnValue;     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F2A[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimespan                              CallFunc_GetAvailabilityDelay_ReturnValue;         // 0x0070(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	struct FTimespan                              CallFunc_GetDefaultDelay_OutDefaultDelay;          // 0x0078(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue;              // 0x0080(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue_1;            // 0x0084(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F2B[0x3];                                     // 0x0089(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue;      // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue_1;    // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQMapActionSettings_C_GetMapActionState) == 0x000008, "Wrong alignment on BP_SQMapActionSettings_C_GetMapActionState");
static_assert(sizeof(BP_SQMapActionSettings_C_GetMapActionState) == 0x000098, "Wrong size on BP_SQMapActionSettings_C_GetMapActionState");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, InPlayer) == 0x000000, "Member 'BP_SQMapActionSettings_C_GetMapActionState::InPlayer' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, ActionState) == 0x000008, "Member 'BP_SQMapActionSettings_C_GetMapActionState::ActionState' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, Cooldown) == 0x00000C, "Member 'BP_SQMapActionSettings_C_GetMapActionState::Cooldown' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_Add_FloatFloat_ReturnValue) == 0x000010, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x000014, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_TryGetActionAvailability_OutUpdatedActionState) == 0x000018, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_TryGetActionAvailability_OutUpdatedActionState' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_TryGetActionAvailability_ReturnValue) == 0x000068, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_TryGetActionAvailability_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GetAvailabilityDelay_ReturnValue) == 0x000070, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GetAvailabilityDelay_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GetDefaultDelay_OutDefaultDelay) == 0x000078, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GetDefaultDelay_OutDefaultDelay' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GetTotalSeconds_ReturnValue) == 0x000080, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GetTotalSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GetTotalSeconds_ReturnValue_1) == 0x000084, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GetTotalSeconds_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x000088, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x00008C, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GreaterEqual_FloatFloat_ReturnValue) == 0x000090, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GreaterEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionState, CallFunc_GreaterEqual_FloatFloat_ReturnValue_1) == 0x000091, "Member 'BP_SQMapActionSettings_C_GetMapActionState::CallFunc_GreaterEqual_FloatFloat_ReturnValue_1' has a wrong offset!");

// Function BP_SQMapActionSettings.BP_SQMapActionSettings_C.GetMapActionStateTime
// 0x00B8 (0x00B8 - 0x0000)
struct BP_SQMapActionSettings_C_GetMapActionStateTime final
{
public:
	class ASQPlayerController*                    InPlayer;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SecondsRemaining;                                  // 0x0008(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SecondsRemainingPercent;                           // 0x000C(0x0004)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Cooldown;                                          // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F2C[0x4];                                     // 0x001C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQAvailabilityState_Action            CallFunc_TryGetActionAvailability_OutUpdatedActionState; // 0x0020(0x0050)(ContainsInstancedReference)
	bool                                          CallFunc_TryGetActionAvailability_ReturnValue;     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F2D[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimespan                              CallFunc_GetAvailabilityDelay_ReturnValue;         // 0x0078(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	struct FTimespan                              CallFunc_GetDefaultDelay_OutDefaultDelay;          // 0x0080(0x0008)(ZeroConstructor, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue;              // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetTotalSeconds_ReturnValue_1;            // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_1;        // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x00A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F2E[0x3];                                     // 0x00A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_2;        // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue;      // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F2F[0x3];                                     // 0x00A9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_2;          // 0x00AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GreaterEqual_FloatFloat_ReturnValue_1;    // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SQMapActionSettings_C_GetMapActionStateTime) == 0x000008, "Wrong alignment on BP_SQMapActionSettings_C_GetMapActionStateTime");
static_assert(sizeof(BP_SQMapActionSettings_C_GetMapActionStateTime) == 0x0000B8, "Wrong size on BP_SQMapActionSettings_C_GetMapActionStateTime");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, InPlayer) == 0x000000, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::InPlayer' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, SecondsRemaining) == 0x000008, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::SecondsRemaining' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, SecondsRemainingPercent) == 0x00000C, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::SecondsRemainingPercent' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, Cooldown) == 0x000010, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::Cooldown' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Add_FloatFloat_ReturnValue) == 0x000014, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x000018, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_TryGetActionAvailability_OutUpdatedActionState) == 0x000020, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_TryGetActionAvailability_OutUpdatedActionState' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_TryGetActionAvailability_ReturnValue) == 0x000070, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_TryGetActionAvailability_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GetAvailabilityDelay_ReturnValue) == 0x000078, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GetAvailabilityDelay_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GetDefaultDelay_OutDefaultDelay) == 0x000080, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GetDefaultDelay_OutDefaultDelay' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GetTotalSeconds_ReturnValue) == 0x000088, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GetTotalSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GetTotalSeconds_ReturnValue_1) == 0x00008C, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GetTotalSeconds_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000090, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Subtract_FloatFloat_ReturnValue_1) == 0x000094, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Subtract_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000098, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x00009C, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x0000A0, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Subtract_FloatFloat_ReturnValue_2) == 0x0000A4, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Subtract_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GreaterEqual_FloatFloat_ReturnValue) == 0x0000A8, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GreaterEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_Divide_FloatFloat_ReturnValue_2) == 0x0000AC, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_Divide_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_SQMapActionSettings_C_GetMapActionStateTime, CallFunc_GreaterEqual_FloatFloat_ReturnValue_1) == 0x0000B0, "Member 'BP_SQMapActionSettings_C_GetMapActionStateTime::CallFunc_GreaterEqual_FloatFloat_ReturnValue_1' has a wrong offset!");

}

