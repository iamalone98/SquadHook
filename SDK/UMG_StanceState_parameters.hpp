#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_StanceState

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "UMG_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function UMG_StanceState.UMG_StanceState_C.ExecuteUbergraph_UMG_StanceState
// 0x0090 (0x0090 - 0x0000)
struct UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_38BC[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              Temp_byte_Variable;                                // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_38BD[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void(class USaveData_UI_C* Data)>   K2Node_CreateDelegate_OutputDelegate;              // 0x0014(0x0010)(ZeroConstructor, NoDestructor)
	ESlateVisibility                              Temp_byte_Variable_1;                              // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0025(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38BE[0x2];                                     // 0x0026(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0028(0x0010)(ZeroConstructor, NoDestructor)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0040(0x0008)(NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQGameInstance*                        CallFunc_GetSquadGameInstance_ReturnValue;         // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0058(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38BF[0x7];                                     // 0x0059(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SquadGameInstance_C*                K2Node_DynamicCast_AsBP_Squad_Game_Instance;       // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C0[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C1[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USaveData_UI_C*                         K2Node_CustomEvent_Data;                           // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESlateVisibility                              K2Node_Select_Default;                             // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsInVehicle_ReturnValue;                  // 0x0089(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x008A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsAlive_ReturnValue;                      // 0x008B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x008C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState) == 0x000008, "Wrong alignment on UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState");
static_assert(sizeof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState) == 0x000090, "Wrong size on UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, EntryPoint) == 0x000000, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::EntryPoint' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000008, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, Temp_byte_Variable) == 0x000010, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::Temp_byte_Variable' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_CreateDelegate_OutputDelegate) == 0x000014, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, Temp_byte_Variable_1) == 0x000024, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::Temp_byte_Variable_1' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, Temp_bool_Variable) == 0x000025, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_CreateDelegate_OutputDelegate_1) == 0x000028, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_GetOwningPlayer_ReturnValue) == 0x000038, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000040, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_K2_GetPawn_ReturnValue) == 0x000048, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_GetSquadGameInstance_ReturnValue) == 0x000050, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_GetSquadGameInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_IsValid_ReturnValue) == 0x000058, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_DynamicCast_AsBP_Squad_Game_Instance) == 0x000060, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_DynamicCast_AsBP_Squad_Game_Instance' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_DynamicCast_bSuccess) == 0x000068, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_DynamicCast_AsSQSoldier) == 0x000070, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_DynamicCast_bSuccess_1) == 0x000078, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_CustomEvent_Data) == 0x000080, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_CustomEvent_Data' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, K2Node_Select_Default) == 0x000088, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_IsInVehicle_ReturnValue) == 0x000089, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_IsInVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_Not_PreBool_ReturnValue) == 0x00008A, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_IsAlive_ReturnValue) == 0x00008B, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_IsAlive_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState, CallFunc_BooleanAND_ReturnValue) == 0x00008C, "Member 'UMG_StanceState_C_ExecuteUbergraph_UMG_StanceState::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function UMG_StanceState.UMG_StanceState_C.Update Stance Visibility
// 0x0008 (0x0008 - 0x0000)
struct UMG_StanceState_C_Update_Stance_Visibility final
{
public:
	class USaveData_UI_C*                         Data;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_StanceState_C_Update_Stance_Visibility) == 0x000008, "Wrong alignment on UMG_StanceState_C_Update_Stance_Visibility");
static_assert(sizeof(UMG_StanceState_C_Update_Stance_Visibility) == 0x000008, "Wrong size on UMG_StanceState_C_Update_Stance_Visibility");
static_assert(offsetof(UMG_StanceState_C_Update_Stance_Visibility, Data) == 0x000000, "Member 'UMG_StanceState_C_Update_Stance_Visibility::Data' has a wrong offset!");

// Function UMG_StanceState.UMG_StanceState_C.UpdateStance
// 0x00A8 (0x00A8 - 0x0000)
struct UMG_StanceState_C_UpdateStance final
{
public:
	class ASQSoldier*                             Soldier;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_MutableSoldier_C*                   K2Node_DynamicCast_AsBP_Mutable_Soldier;           // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C2[0x3];                                     // 0x0011(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Conv_BoolToFloat_ReturnValue;             // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C3[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Conv_BoolToFloat_ReturnValue_1;           // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush;                      // 0x0020(0x0088)()
};
static_assert(alignof(UMG_StanceState_C_UpdateStance) == 0x000008, "Wrong alignment on UMG_StanceState_C_UpdateStance");
static_assert(sizeof(UMG_StanceState_C_UpdateStance) == 0x0000A8, "Wrong size on UMG_StanceState_C_UpdateStance");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, Soldier) == 0x000000, "Member 'UMG_StanceState_C_UpdateStance::Soldier' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, K2Node_DynamicCast_AsBP_Mutable_Soldier) == 0x000008, "Member 'UMG_StanceState_C_UpdateStance::K2Node_DynamicCast_AsBP_Mutable_Soldier' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, K2Node_DynamicCast_bSuccess) == 0x000010, "Member 'UMG_StanceState_C_UpdateStance::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, CallFunc_Conv_BoolToFloat_ReturnValue) == 0x000014, "Member 'UMG_StanceState_C_UpdateStance::CallFunc_Conv_BoolToFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, CallFunc_Not_PreBool_ReturnValue) == 0x000018, "Member 'UMG_StanceState_C_UpdateStance::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, CallFunc_Conv_BoolToFloat_ReturnValue_1) == 0x00001C, "Member 'UMG_StanceState_C_UpdateStance::CallFunc_Conv_BoolToFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateStance, K2Node_MakeStruct_SlateBrush) == 0x000020, "Member 'UMG_StanceState_C_UpdateStance::K2Node_MakeStruct_SlateBrush' has a wrong offset!");

// Function UMG_StanceState.UMG_StanceState_C.UpdateLean
// 0x00B0 (0x00B0 - 0x0000)
struct UMG_StanceState_C_UpdateLean final
{
public:
	class ASQSoldier*                             Soldier;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Temp_bool_Variable;                                // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0009(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C4[0x2];                                     // 0x000A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Conv_ByteToInt_ReturnValue;               // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue_1;          // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C5[0x6];                                     // 0x0012(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                K2Node_Select_Default;                             // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateBrush                            K2Node_MakeStruct_SlateBrush;                      // 0x0020(0x0088)()
	bool                                          CallFunc_NotEqual_ObjectObject_ReturnValue;        // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UMG_StanceState_C_UpdateLean) == 0x000008, "Wrong alignment on UMG_StanceState_C_UpdateLean");
static_assert(sizeof(UMG_StanceState_C_UpdateLean) == 0x0000B0, "Wrong size on UMG_StanceState_C_UpdateLean");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, Soldier) == 0x000000, "Member 'UMG_StanceState_C_UpdateLean::Soldier' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, Temp_bool_Variable) == 0x000008, "Member 'UMG_StanceState_C_UpdateLean::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, CallFunc_IsValid_ReturnValue) == 0x000009, "Member 'UMG_StanceState_C_UpdateLean::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, CallFunc_Conv_ByteToInt_ReturnValue) == 0x00000C, "Member 'UMG_StanceState_C_UpdateLean::CallFunc_Conv_ByteToInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000010, "Member 'UMG_StanceState_C_UpdateLean::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, CallFunc_EqualEqual_IntInt_ReturnValue_1) == 0x000011, "Member 'UMG_StanceState_C_UpdateLean::CallFunc_EqualEqual_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, K2Node_Select_Default) == 0x000018, "Member 'UMG_StanceState_C_UpdateLean::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, K2Node_MakeStruct_SlateBrush) == 0x000020, "Member 'UMG_StanceState_C_UpdateLean::K2Node_MakeStruct_SlateBrush' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateLean, CallFunc_NotEqual_ObjectObject_ReturnValue) == 0x0000A8, "Member 'UMG_StanceState_C_UpdateLean::CallFunc_NotEqual_ObjectObject_ReturnValue' has a wrong offset!");

// Function UMG_StanceState.UMG_StanceState_C.UpdateBleeding
// 0x0020 (0x0020 - 0x0000)
struct UMG_StanceState_C_UpdateBleeding final
{
public:
	class ASQSoldier*                             Soldier;                                           // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_38C6[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue_1;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_StanceState_C_UpdateBleeding) == 0x000008, "Wrong alignment on UMG_StanceState_C_UpdateBleeding");
static_assert(sizeof(UMG_StanceState_C_UpdateBleeding) == 0x000020, "Wrong size on UMG_StanceState_C_UpdateBleeding");
static_assert(offsetof(UMG_StanceState_C_UpdateBleeding, Soldier) == 0x000000, "Member 'UMG_StanceState_C_UpdateBleeding::Soldier' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateBleeding, CallFunc_PlayAnimation_ReturnValue) == 0x000008, "Member 'UMG_StanceState_C_UpdateBleeding::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateBleeding, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'UMG_StanceState_C_UpdateBleeding::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_StanceState_C_UpdateBleeding, CallFunc_PlayAnimation_ReturnValue_1) == 0x000018, "Member 'UMG_StanceState_C_UpdateBleeding::CallFunc_PlayAnimation_ReturnValue_1' has a wrong offset!");

}

