#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GameMode

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_GameMode.BP_GameMode_C.ExecuteUbergraph_BP_GameMode
// 0x0040 (0x0040 - 0x0000)
struct BP_GameMode_C_ExecuteUbergraph_BP_GameMode final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4AB0[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class ASQForwardBase*>                 CallFunc_GetAllActorsOfClass_OutActors;            // 0x0008(0x0010)(ReferenceParm)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4AB1[0x4];                                     // 0x0024(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQForwardBase*                         CallFunc_Array_Get_Item;                           // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB2[0x3];                                     // 0x0031(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0034(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EEndPlayReason                                K2Node_Event_EndPlayReason;                        // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode) == 0x000008, "Wrong alignment on BP_GameMode_C_ExecuteUbergraph_BP_GameMode");
static_assert(sizeof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode) == 0x000040, "Wrong size on BP_GameMode_C_ExecuteUbergraph_BP_GameMode");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, EntryPoint) == 0x000000, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, CallFunc_GetAllActorsOfClass_OutActors) == 0x000008, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::CallFunc_GetAllActorsOfClass_OutActors' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, CallFunc_Array_Length_ReturnValue) == 0x000018, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, Temp_int_Array_Index_Variable) == 0x00001C, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, Temp_int_Loop_Counter_Variable) == 0x000020, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, CallFunc_Array_Get_Item) == 0x000028, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, CallFunc_Less_IntInt_ReturnValue) == 0x000030, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, CallFunc_Add_IntInt_ReturnValue) == 0x000034, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_ExecuteUbergraph_BP_GameMode, K2Node_Event_EndPlayReason) == 0x000038, "Member 'BP_GameMode_C_ExecuteUbergraph_BP_GameMode::K2Node_Event_EndPlayReason' has a wrong offset!");

// Function BP_GameMode.BP_GameMode_C.ReceiveEndPlay
// 0x0001 (0x0001 - 0x0000)
struct BP_GameMode_C_ReceiveEndPlay final
{
public:
	EEndPlayReason                                EndPlayReason;                                     // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GameMode_C_ReceiveEndPlay) == 0x000001, "Wrong alignment on BP_GameMode_C_ReceiveEndPlay");
static_assert(sizeof(BP_GameMode_C_ReceiveEndPlay) == 0x000001, "Wrong size on BP_GameMode_C_ReceiveEndPlay");
static_assert(offsetof(BP_GameMode_C_ReceiveEndPlay, EndPlayReason) == 0x000000, "Member 'BP_GameMode_C_ReceiveEndPlay::EndPlayReason' has a wrong offset!");

// Function BP_GameMode.BP_GameMode_C.GetConcretePawnClassForController
// 0x0100 (0x0100 - 0x0000)
struct BP_GameMode_C_GetConcretePawnClassForController final
{
public:
	class AController*                            InController;                                      // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSubclassOf<class ASQSoldier>                 ReturnValue;                                       // 0x0008(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash)
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB3[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB4[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        CallFunc_GetCurrentRole_ReturnValue;               // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB5[0x6];                                     // 0x003A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB6[0x7];                                     // 0x0049(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSoftClassPtr<class UClass>                   CallFunc_TryGetSoldierWithLayer_OutSoldier;        // 0x0050(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetSoldierWithLayer_ReturnValue;       // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0079(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB7[0x6];                                     // 0x007A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TSubclassOf<class UObject>                    CallFunc_Conv_SoftClassReferenceToClass_ReturnValue; // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash)
	class UClass*                                 CallFunc_LoadClassAsset_Blocking_ReturnValue;      // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 K2Node_ClassDynamicCast_AsSQSoldier;               // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_ClassDynamicCast_bSuccess;                  // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB8[0x7];                                     // 0x0099(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings_1;         // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4AB9[0x7];                                     // 0x00A9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSoftClassPtr<class UClass>                   CallFunc_TryGetSoldierWithLayer_OutSoldier_1;      // 0x00B0(0x0028)(UObjectWrapper, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetSoldierWithLayer_ReturnValue_1;     // 0x00D8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4ABA[0x7];                                     // 0x00D9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 CallFunc_LoadClassAsset_Blocking_ReturnValue_1;    // 0x00E0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSubclassOf<class UObject>                    CallFunc_Conv_SoftClassReferenceToClass_ReturnValue_1; // 0x00E8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash)
	class UClass*                                 K2Node_ClassDynamicCast_AsSQSoldier_1;             // 0x00F0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_ClassDynamicCast_bSuccess_1;                // 0x00F8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GameMode_C_GetConcretePawnClassForController) == 0x000008, "Wrong alignment on BP_GameMode_C_GetConcretePawnClassForController");
static_assert(sizeof(BP_GameMode_C_GetConcretePawnClassForController) == 0x000100, "Wrong size on BP_GameMode_C_GetConcretePawnClassForController");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, InController) == 0x000000, "Member 'BP_GameMode_C_GetConcretePawnClassForController::InController' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, ReturnValue) == 0x000008, "Member 'BP_GameMode_C_GetConcretePawnClassForController::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000010, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000018, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_AsSQPlayer_State) == 0x000020, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_GetCurrentRole_ReturnValue) == 0x000030, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_GetCurrentRole_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_IsValid_ReturnValue) == 0x000038, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_IsValid_ReturnValue_1) == 0x000039, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x000040, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_bSuccess_1) == 0x000048, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetSoldierWithLayer_OutSoldier) == 0x000050, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetSoldierWithLayer_OutSoldier' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetSoldierWithLayer_ReturnValue) == 0x000078, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetSoldierWithLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_IsValid_ReturnValue_2) == 0x000079, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_Conv_SoftClassReferenceToClass_ReturnValue) == 0x000080, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_Conv_SoftClassReferenceToClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_LoadClassAsset_Blocking_ReturnValue) == 0x000088, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_LoadClassAsset_Blocking_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_ClassDynamicCast_AsSQSoldier) == 0x000090, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_ClassDynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_ClassDynamicCast_bSuccess) == 0x000098, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_ClassDynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_AsBP_SQRole_Settings_1) == 0x0000A0, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_AsBP_SQRole_Settings_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_DynamicCast_bSuccess_2) == 0x0000A8, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetSoldierWithLayer_OutSoldier_1) == 0x0000B0, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetSoldierWithLayer_OutSoldier_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_TryGetSoldierWithLayer_ReturnValue_1) == 0x0000D8, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_TryGetSoldierWithLayer_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_LoadClassAsset_Blocking_ReturnValue_1) == 0x0000E0, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_LoadClassAsset_Blocking_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, CallFunc_Conv_SoftClassReferenceToClass_ReturnValue_1) == 0x0000E8, "Member 'BP_GameMode_C_GetConcretePawnClassForController::CallFunc_Conv_SoftClassReferenceToClass_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_ClassDynamicCast_AsSQSoldier_1) == 0x0000F0, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_ClassDynamicCast_AsSQSoldier_1' has a wrong offset!");
static_assert(offsetof(BP_GameMode_C_GetConcretePawnClassForController, K2Node_ClassDynamicCast_bSuccess_1) == 0x0000F8, "Member 'BP_GameMode_C_GetConcretePawnClassForController::K2Node_ClassDynamicCast_bSuccess_1' has a wrong offset!");

}
