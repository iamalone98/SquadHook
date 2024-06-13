#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BaseFobCreator

#include "Basic.hpp"

#include "S_FOBRadius_structs.hpp"
#include "Squad_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.ExecuteUbergraph_BP_BaseFobCreator
// 0x00A8 (0x00A8 - 0x0000)
struct BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0011(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23EC[0x2];                                     // 0x0012(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x001C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_TimerExistsHandle_ReturnValue;         // 0x0022(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsGhost_ReturnValue;                      // 0x0023(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	int32                                         Temp_int_Variable;                                 // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EEndPlayReason                                K2Node_Event_EndPlayReason;                        // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0029(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23ED[0x6];                                     // 0x002A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AController*                            K2Node_Event_User_1;                               // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AController*                            K2Node_Event_User;                                 // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_Event_bFriendly;                            // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23EE[0x3];                                     // 0x0041(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_Event_Difference;                           // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQGameSpawn*                           CallFunc_Array_Get_Item;                           // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class AActor*>                         CallFunc_GetOverlappingActors_OverlappingActors;   // 0x0050(0x0010)(ReferenceParm)
	class ABP_ForwardBaseSpawn_C*                 K2Node_DynamicCast_AsBP_Forward_Base_Spawn;        // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23EF[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_Array_Get_Item_1;                         // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F0[0x3];                                     // 0x0081(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetTeam_ReturnValue;                      // 0x0084(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_IntInt_ReturnValue;              // 0x0092(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F1[0x1];                                     // 0x0093(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue_2;                 // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsGhost_ReturnValue_1;                    // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F2[0x3];                                     // 0x0099(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Multiply_IntFloat_ReturnValue;            // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator) == 0x000008, "Wrong alignment on BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator");
static_assert(sizeof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator) == 0x0000A8, "Wrong size on BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, EntryPoint) == 0x000000, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, Temp_int_Array_Index_Variable) == 0x00000C, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_HasAuthority_ReturnValue) == 0x000011, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, Temp_int_Loop_Counter_Variable_1) == 0x000014, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Add_IntInt_ReturnValue_1) == 0x000018, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, Temp_int_Array_Index_Variable_1) == 0x00001C, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsValid_ReturnValue_1) == 0x000020, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsValid_ReturnValue_2) == 0x000021, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_K2_TimerExistsHandle_ReturnValue) == 0x000022, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_K2_TimerExistsHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsGhost_ReturnValue) == 0x000023, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsGhost_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, Temp_int_Variable) == 0x000024, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_Event_EndPlayReason) == 0x000028, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_Event_EndPlayReason' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsValid_ReturnValue_3) == 0x000029, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_Event_User_1) == 0x000030, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_Event_User_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_Event_User) == 0x000038, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_Event_User' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_Event_bFriendly) == 0x000040, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_Event_bFriendly' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_Event_Difference) == 0x000044, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_Event_Difference' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Array_Get_Item) == 0x000048, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_GetOverlappingActors_OverlappingActors) == 0x000050, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_GetOverlappingActors_OverlappingActors' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_DynamicCast_AsBP_Forward_Base_Spawn) == 0x000060, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_DynamicCast_AsBP_Forward_Base_Spawn' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_DynamicCast_bSuccess) == 0x000068, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Array_Get_Item_1) == 0x000070, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_DynamicCast_AsSQSoldier) == 0x000078, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, K2Node_DynamicCast_bSuccess_1) == 0x000080, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_GetTeam_ReturnValue) == 0x000084, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_GetTeam_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Array_Length_ReturnValue) == 0x000088, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Array_Length_ReturnValue_1) == 0x00008C, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Less_IntInt_ReturnValue) == 0x000090, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Less_IntInt_ReturnValue_1) == 0x000091, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_NotEqual_IntInt_ReturnValue) == 0x000092, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_NotEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Add_IntInt_ReturnValue_2) == 0x000094, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Add_IntInt_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_IsGhost_ReturnValue_1) == 0x000098, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_IsGhost_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Multiply_IntFloat_ReturnValue) == 0x00009C, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Multiply_IntFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000A0, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x0000A4, "Member 'BP_BaseFobCreator_C_ExecuteUbergraph_BP_BaseFobCreator::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.BPPostTicketTick
// 0x0004 (0x0004 - 0x0000)
struct BP_BaseFobCreator_C_BPPostTicketTick final
{
public:
	float                                         Difference;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_BPPostTicketTick) == 0x000004, "Wrong alignment on BP_BaseFobCreator_C_BPPostTicketTick");
static_assert(sizeof(BP_BaseFobCreator_C_BPPostTicketTick) == 0x000004, "Wrong size on BP_BaseFobCreator_C_BPPostTicketTick");
static_assert(offsetof(BP_BaseFobCreator_C_BPPostTicketTick, Difference) == 0x000000, "Member 'BP_BaseFobCreator_C_BPPostTicketTick::Difference' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.BPOverrun
// 0x0001 (0x0001 - 0x0000)
struct BP_BaseFobCreator_C_BPOverrun final
{
public:
	bool                                          bFriendly;                                         // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_BaseFobCreator_C_BPOverrun) == 0x000001, "Wrong alignment on BP_BaseFobCreator_C_BPOverrun");
static_assert(sizeof(BP_BaseFobCreator_C_BPOverrun) == 0x000001, "Wrong size on BP_BaseFobCreator_C_BPOverrun");
static_assert(offsetof(BP_BaseFobCreator_C_BPOverrun, bFriendly) == 0x000000, "Member 'BP_BaseFobCreator_C_BPOverrun::bFriendly' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.BPStopUsed
// 0x0008 (0x0008 - 0x0000)
struct BP_BaseFobCreator_C_BPStopUsed final
{
public:
	class AController*                            User;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_BPStopUsed) == 0x000008, "Wrong alignment on BP_BaseFobCreator_C_BPStopUsed");
static_assert(sizeof(BP_BaseFobCreator_C_BPStopUsed) == 0x000008, "Wrong size on BP_BaseFobCreator_C_BPStopUsed");
static_assert(offsetof(BP_BaseFobCreator_C_BPStopUsed, User) == 0x000000, "Member 'BP_BaseFobCreator_C_BPStopUsed::User' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.BPOnUsed
// 0x0008 (0x0008 - 0x0000)
struct BP_BaseFobCreator_C_BPOnUsed final
{
public:
	class AController*                            User;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_BPOnUsed) == 0x000008, "Wrong alignment on BP_BaseFobCreator_C_BPOnUsed");
static_assert(sizeof(BP_BaseFobCreator_C_BPOnUsed) == 0x000008, "Wrong size on BP_BaseFobCreator_C_BPOnUsed");
static_assert(offsetof(BP_BaseFobCreator_C_BPOnUsed, User) == 0x000000, "Member 'BP_BaseFobCreator_C_BPOnUsed::User' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.ReceiveEndPlay
// 0x0001 (0x0001 - 0x0000)
struct BP_BaseFobCreator_C_ReceiveEndPlay final
{
public:
	EEndPlayReason                                EndPlayReason;                                     // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_ReceiveEndPlay) == 0x000001, "Wrong alignment on BP_BaseFobCreator_C_ReceiveEndPlay");
static_assert(sizeof(BP_BaseFobCreator_C_ReceiveEndPlay) == 0x000001, "Wrong size on BP_BaseFobCreator_C_ReceiveEndPlay");
static_assert(offsetof(BP_BaseFobCreator_C_ReceiveEndPlay, EndPlayReason) == 0x000000, "Member 'BP_BaseFobCreator_C_ReceiveEndPlay::EndPlayReason' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.UserConstructionScript
// 0x0050 (0x0050 - 0x0000)
struct BP_BaseFobCreator_C_UserConstructionScript final
{
public:
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F3[0xF];                                     // 0x0001(0x000F)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTransform                             CallFunc_GetRelativeTransform_ReturnValue;         // 0x0010(0x0030)(IsPlainOldData, NoDestructor)
	class UParticleSystemComponent*               CallFunc_AddComponent_ReturnValue;                 // 0x0040(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_UserConstructionScript) == 0x000010, "Wrong alignment on BP_BaseFobCreator_C_UserConstructionScript");
static_assert(sizeof(BP_BaseFobCreator_C_UserConstructionScript) == 0x000050, "Wrong size on BP_BaseFobCreator_C_UserConstructionScript");
static_assert(offsetof(BP_BaseFobCreator_C_UserConstructionScript, CallFunc_HasAuthority_ReturnValue) == 0x000000, "Member 'BP_BaseFobCreator_C_UserConstructionScript::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_UserConstructionScript, CallFunc_GetRelativeTransform_ReturnValue) == 0x000010, "Member 'BP_BaseFobCreator_C_UserConstructionScript::CallFunc_GetRelativeTransform_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_UserConstructionScript, CallFunc_AddComponent_ReturnValue) == 0x000040, "Member 'BP_BaseFobCreator_C_UserConstructionScript::CallFunc_AddComponent_ReturnValue' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.Remove Nearby FOB Request Markers
// 0x00E8 (0x00E8 - 0x0000)
struct BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers final
{
public:
	float                                         Radius;                                            // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_23F4[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQMapMarkerManagerComponent*           MarkerManager;                                     // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F5[0x3];                                     // 0x0015(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQLayer_C*                          CallFunc_TryGetCurrentLayer_OutLayer;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_TryGetCurrentLayer_ReturnValue;           // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F6[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FDataTableRowHandle                    CallFunc_GetFobRadiusTableRow_ReturnValue;         // 0x0028(0x0010)(ConstParm, NoDestructor)
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x0038(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsGhost_ReturnValue;                      // 0x0044(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F7[0x3];                                     // 0x0045(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FS_FOBRadius                           CallFunc_GetDataTableRowFromName_OutRow;           // 0x0048(0x0020)(HasGetValueTypeHash)
	bool                                          CallFunc_GetDataTableRowFromName_ReturnValue;      // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0069(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23F8[0x6];                                     // 0x006A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<struct FSQMapMarkerGameplayData>       CallFunc_FindMapMarkersByType_OutMarkers;          // 0x0070(0x0010)(ReferenceParm)
	struct FSQMapMarkerGameplayData               CallFunc_Array_Get_Item;                           // 0x0080(0x0038)(NoDestructor)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTeamId_ReturnValue;                    // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         CallFunc_Conv_IntToByte_ReturnValue;               // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_23F9[0x3];                                     // 0x00C1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Vector_Distance2D_ReturnValue;            // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_ByteByte_ReturnValue;          // 0x00C8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_LessEqual_FloatFloat_ReturnValue;         // 0x00C9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23FA[0x2];                                     // 0x00CA(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x00CC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x00D1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23FB[0x2];                                     // 0x00D2(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x00D4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQGameState*                           CallFunc_GetSquadGameState_Return_Value;           // 0x00D8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQMapMarkerManagerComponent*           CallFunc_GetMarkerManager_ReturnValue;             // 0x00E0(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers) == 0x000008, "Wrong alignment on BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers");
static_assert(sizeof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers) == 0x0000E8, "Wrong size on BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, Radius) == 0x000000, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::Radius' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, MarkerManager) == 0x000008, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::MarkerManager' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, Temp_int_Array_Index_Variable) == 0x000010, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_HasAuthority_ReturnValue) == 0x000014, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_TryGetCurrentLayer_OutLayer) == 0x000018, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_TryGetCurrentLayer_OutLayer' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_TryGetCurrentLayer_ReturnValue) == 0x000020, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_TryGetCurrentLayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetFobRadiusTableRow_ReturnValue) == 0x000028, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetFobRadiusTableRow_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_K2_GetActorLocation_ReturnValue) == 0x000038, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_IsGhost_ReturnValue) == 0x000044, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_IsGhost_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetDataTableRowFromName_OutRow) == 0x000048, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetDataTableRowFromName_OutRow' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetDataTableRowFromName_ReturnValue) == 0x000068, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetDataTableRowFromName_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Not_PreBool_ReturnValue) == 0x000069, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_FindMapMarkersByType_OutMarkers) == 0x000070, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_FindMapMarkersByType_OutMarkers' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Array_Get_Item) == 0x000080, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Array_Length_ReturnValue) == 0x0000B8, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetTeamId_ReturnValue) == 0x0000BC, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetTeamId_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Conv_IntToByte_ReturnValue) == 0x0000C0, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Conv_IntToByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Vector_Distance2D_ReturnValue) == 0x0000C4, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Vector_Distance2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_EqualEqual_ByteByte_ReturnValue) == 0x0000C8, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_EqualEqual_ByteByte_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_LessEqual_FloatFloat_ReturnValue) == 0x0000C9, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_LessEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, Temp_int_Loop_Counter_Variable) == 0x0000CC, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_BooleanAND_ReturnValue) == 0x0000D0, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Less_IntInt_ReturnValue) == 0x0000D1, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_Add_IntInt_ReturnValue) == 0x0000D4, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetSquadGameState_Return_Value) == 0x0000D8, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetSquadGameState_Return_Value' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers, CallFunc_GetMarkerManager_ReturnValue) == 0x0000E0, "Member 'BP_BaseFobCreator_C_Remove_Nearby_FOB_Request_Markers::CallFunc_GetMarkerManager_ReturnValue' has a wrong offset!");

// Function BP_BaseFobCreator.BP_BaseFobCreator_C.GetUsableData
// 0x0098 (0x0098 - 0x0000)
struct BP_BaseFobCreator_C_GetUsableData final
{
public:
	struct FSQUsableData                          ReturnValue;                                       // 0x0000(0x0040)(Parm, OutParm, ReturnParm)
	bool                                          Temp_bool_Variable;                                // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23FC[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetTeam_ReturnValue;                      // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_EqualEqual_IntInt_ReturnValue;            // 0x0054(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_23FD[0x3];                                     // 0x0055(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQUsableData                          K2Node_Select_Default;                             // 0x0058(0x0040)()
};
static_assert(alignof(BP_BaseFobCreator_C_GetUsableData) == 0x000008, "Wrong alignment on BP_BaseFobCreator_C_GetUsableData");
static_assert(sizeof(BP_BaseFobCreator_C_GetUsableData) == 0x000098, "Wrong size on BP_BaseFobCreator_C_GetUsableData");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, ReturnValue) == 0x000000, "Member 'BP_BaseFobCreator_C_GetUsableData::ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, Temp_bool_Variable) == 0x000040, "Member 'BP_BaseFobCreator_C_GetUsableData::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, CallFunc_GetSquadPlayerController_Return_Value) == 0x000048, "Member 'BP_BaseFobCreator_C_GetUsableData::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, CallFunc_GetTeam_ReturnValue) == 0x000050, "Member 'BP_BaseFobCreator_C_GetUsableData::CallFunc_GetTeam_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, CallFunc_EqualEqual_IntInt_ReturnValue) == 0x000054, "Member 'BP_BaseFobCreator_C_GetUsableData::CallFunc_EqualEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_BaseFobCreator_C_GetUsableData, K2Node_Select_Default) == 0x000058, "Member 'BP_BaseFobCreator_C_GetUsableData::K2Node_Select_Default' has a wrong offset!");

}

