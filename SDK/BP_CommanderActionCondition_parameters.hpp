#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_CommanderActionCondition

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function BP_CommanderActionCondition.BP_CommanderActionCondition_C.Can Use Actions
// 0x00D0 (0x00D0 - 0x0000)
struct BP_CommanderActionCondition_C_Can_Use_Actions final
{
public:
	class ASQPlayerController*                    Player;                                            // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Command_Option;                                    // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Require_Active;                                    // 0x0010(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Valid;                                             // 0x0011(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_467C[0x6];                                     // 0x0012(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Out_Reason;                                        // 0x0018(0x0018)(Parm, OutParm)
	bool                                          Temp_bool_Variable;                                // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_467D[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   Temp_text_Variable;                                // 0x0038(0x0018)()
	class FText                                   Temp_text_Variable_1;                              // 0x0050(0x0018)()
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0069(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x006A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_467E[0x5];                                     // 0x006B(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_467F[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        CallFunc_GetCurrentRole_ReturnValue;               // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4680[0x7];                                     // 0x0089(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQFactionSetup_C*                   K2Node_DynamicCast_AsBP_SQFaction_Setup;           // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4681[0x7];                                     // 0x0099(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   K2Node_Select_Default;                             // 0x00A0(0x0018)()
	ESQCommandOptionState                         CallFunc_CalculateState_ReturnValue;               // 0x00B8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x00B9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_GetActionsEnabled_ReturnValue;            // 0x00BA(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_CanUseAction_ReturnValue;                 // 0x00BB(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4682[0x4];                                     // 0x00BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        CallFunc_GetCurrentRole_ReturnValue_1;             // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsCommander_ReturnValue;                  // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsSquadLeader_ReturnValue;                // 0x00C9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x00CA(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue_1;                // 0x00CB(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsInVehicle_ReturnValue;                  // 0x00CC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue_2;                // 0x00CD(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00CE(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_CommanderActionCondition_C_Can_Use_Actions) == 0x000008, "Wrong alignment on BP_CommanderActionCondition_C_Can_Use_Actions");
static_assert(sizeof(BP_CommanderActionCondition_C_Can_Use_Actions) == 0x0000D0, "Wrong size on BP_CommanderActionCondition_C_Can_Use_Actions");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Player) == 0x000000, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Player' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Command_Option) == 0x000008, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Command_Option' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Require_Active) == 0x000010, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Require_Active' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Valid) == 0x000011, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Valid' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Out_Reason) == 0x000018, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Out_Reason' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Temp_bool_Variable) == 0x000030, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Temp_text_Variable) == 0x000038, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Temp_text_Variable' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, Temp_text_Variable_1) == 0x000050, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::Temp_text_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsValid_ReturnValue) == 0x000068, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsValid_ReturnValue_1) == 0x000069, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsValid_ReturnValue_2) == 0x00006A, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_K2_GetPawn_ReturnValue) == 0x000070, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsValid_ReturnValue_3) == 0x000078, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_GetCurrentRole_ReturnValue) == 0x000080, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_GetCurrentRole_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsValid_ReturnValue_4) == 0x000088, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, K2Node_DynamicCast_AsBP_SQFaction_Setup) == 0x000090, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::K2Node_DynamicCast_AsBP_SQFaction_Setup' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, K2Node_DynamicCast_bSuccess) == 0x000098, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, K2Node_Select_Default) == 0x0000A0, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_CalculateState_ReturnValue) == 0x0000B8, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_CalculateState_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x0000B9, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_GetActionsEnabled_ReturnValue) == 0x0000BA, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_GetActionsEnabled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_CanUseAction_ReturnValue) == 0x0000BB, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_CanUseAction_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_GetCurrentRole_ReturnValue_1) == 0x0000C0, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_GetCurrentRole_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsCommander_ReturnValue) == 0x0000C8, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsCommander_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsSquadLeader_ReturnValue) == 0x0000C9, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsSquadLeader_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_Not_PreBool_ReturnValue) == 0x0000CA, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_Not_PreBool_ReturnValue_1) == 0x0000CB, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_Not_PreBool_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_IsInVehicle_ReturnValue) == 0x0000CC, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_IsInVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_Not_PreBool_ReturnValue_2) == 0x0000CD, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_Not_PreBool_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_CommanderActionCondition_C_Can_Use_Actions, CallFunc_BooleanAND_ReturnValue) == 0x0000CE, "Member 'BP_CommanderActionCondition_C_Can_Use_Actions::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

}
