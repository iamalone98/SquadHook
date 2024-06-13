#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Phone_Detonator

#include "Basic.hpp"

#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_Phone_Detonator.BP_Phone_Detonator_C.ExecuteUbergraph_BP_Phone_Detonator
// 0x00D8 (0x00D8 - 0x0000)
struct BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	float                                         K2Node_CustomEvent_Detonation_Delay;               // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQItemStaticInfo*                      CallFunc_GetItemStaticInfo_ReturnValue;            // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQDetonatorStaticInfo*                 K2Node_DynamicCast_AsSQDetonator_Static_Info;      // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF4[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USQItemStaticInfo*                      CallFunc_GetItemStaticInfo_ReturnValue_1;          // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQDetonatorStaticInfo*                 K2Node_DynamicCast_AsSQDetonator_Static_Info_1;    // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF5[0x3];                                     // 0x0041(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakVector2D_X;                          // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValidClass_ReturnValue;                 // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF6[0x3];                                     // 0x004D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_RandomFloatInRange_ReturnValue;           // 0x0050(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_ExplosivesReady_Valid;                    // 0x0054(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF7[0x3];                                     // 0x0055(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UUserWidget*                            CallFunc_GetUserWidgetObject_ReturnValue;          // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_IED_Dialling_C*                      K2Node_DynamicCast_AsW_IED_Dialling;               // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF8[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AController*                            CallFunc_GetInstigatorController_ReturnValue;      // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      K2Node_DynamicCast_AsPlayer_Controller;            // 0x0078(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_3;                     // 0x0080(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsLocalPlayerController_ReturnValue;      // 0x0081(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0082(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BF9[0x5];                                     // 0x0083(0x0005)(Fixing Size After Last Property [ Dumper-7 ])
	class AController*                            CallFunc_GetInstigatorController_ReturnValue_1;    // 0x0088(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      K2Node_DynamicCast_AsPlayer_Controller_1;          // 0x0090(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_4;                     // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0099(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFA[0x6];                                     // 0x009A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_5;                     // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_HasAuthority_ReturnValue;                 // 0x00A9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_IsTimerActiveHandle_ReturnValue;       // 0x00AA(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x00AB(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_Variable;                                // 0x00AC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFB[0x3];                                     // 0x00AD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x00B0(0x0008)(NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Select_Default;                             // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x00BC(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFC[0x3];                                     // 0x00BD(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x00C0(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue_1;        // 0x00D0(0x0008)(NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator) == 0x000008, "Wrong alignment on BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator");
static_assert(sizeof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator) == 0x0000D8, "Wrong size on BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, EntryPoint) == 0x000000, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_CustomEvent_Detonation_Delay) == 0x000014, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_CustomEvent_Detonation_Delay' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_GetItemStaticInfo_ReturnValue) == 0x000018, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_GetItemStaticInfo_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsSQDetonator_Static_Info) == 0x000020, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsSQDetonator_Static_Info' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess) == 0x000028, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_GetItemStaticInfo_ReturnValue_1) == 0x000030, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_GetItemStaticInfo_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsSQDetonator_Static_Info_1) == 0x000038, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsSQDetonator_Static_Info_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess_1) == 0x000040, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_BreakVector2D_X) == 0x000044, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_BreakVector2D_Y) == 0x000048, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsValidClass_ReturnValue) == 0x00004C, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsValidClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_RandomFloatInRange_ReturnValue) == 0x000050, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_RandomFloatInRange_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_ExplosivesReady_Valid) == 0x000054, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_ExplosivesReady_Valid' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_GetUserWidgetObject_ReturnValue) == 0x000058, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_GetUserWidgetObject_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsW_IED_Dialling) == 0x000060, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsW_IED_Dialling' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess_2) == 0x000068, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_GetInstigatorController_ReturnValue) == 0x000070, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_GetInstigatorController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsPlayer_Controller) == 0x000078, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsPlayer_Controller' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess_3) == 0x000080, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess_3' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsLocalPlayerController_ReturnValue) == 0x000081, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsLocalPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsValid_ReturnValue) == 0x000082, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_GetInstigatorController_ReturnValue_1) == 0x000088, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_GetInstigatorController_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsPlayer_Controller_1) == 0x000090, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsPlayer_Controller_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess_4) == 0x000098, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess_4' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsValid_ReturnValue_1) == 0x000099, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_AsSQPlayer_State) == 0x0000A0, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_DynamicCast_bSuccess_5) == 0x0000A8, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_DynamicCast_bSuccess_5' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_HasAuthority_ReturnValue) == 0x0000A9, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_HasAuthority_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_K2_IsTimerActiveHandle_ReturnValue) == 0x0000AA, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_K2_IsTimerActiveHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsValid_ReturnValue_2) == 0x0000AB, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, Temp_bool_Variable) == 0x0000AC, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x0000B0, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_Select_Default) == 0x0000B8, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_IsValid_ReturnValue_3) == 0x0000BC, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, K2Node_CreateDelegate_OutputDelegate_1) == 0x0000C0, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator, CallFunc_K2_SetTimerDelegate_ReturnValue_1) == 0x0000D0, "Member 'BP_Phone_Detonator_C_ExecuteUbergraph_BP_Phone_Detonator::CallFunc_K2_SetTimerDelegate_ReturnValue_1' has a wrong offset!");

// Function BP_Phone_Detonator.BP_Phone_Detonator_C.Server Initiate Detonation
// 0x0004 (0x0004 - 0x0000)
struct BP_Phone_Detonator_C_Server_Initiate_Detonation final
{
public:
	float                                         Detonation_Delay;                                  // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_Phone_Detonator_C_Server_Initiate_Detonation) == 0x000004, "Wrong alignment on BP_Phone_Detonator_C_Server_Initiate_Detonation");
static_assert(sizeof(BP_Phone_Detonator_C_Server_Initiate_Detonation) == 0x000004, "Wrong size on BP_Phone_Detonator_C_Server_Initiate_Detonation");
static_assert(offsetof(BP_Phone_Detonator_C_Server_Initiate_Detonation, Detonation_Delay) == 0x000000, "Member 'BP_Phone_Detonator_C_Server_Initiate_Detonation::Detonation_Delay' has a wrong offset!");

// Function BP_Phone_Detonator.BP_Phone_Detonator_C.ExplosivesReady
// 0x0050 (0x0050 - 0x0000)
struct BP_Phone_Detonator_C_ExplosivesReady final
{
public:
	class UClass*                                 ExplosivesClass;                                   // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Valid;                                             // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFD[0x3];                                     // 0x0009(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Temp_int_Variable;                                 // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0014(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFE[0x3];                                     // 0x0015(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_GetPlacedDeployableItemsCount_ReturnValue; // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4BFF[0x3];                                     // 0x001D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4C00[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQDeployable*                          CallFunc_GetPlacedDeployableAt_ReturnValue;        // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 CallFunc_GetObjectClass_ReturnValue;               // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ClassClass_ReturnValue;        // 0x0039(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4C01[0x6];                                     // 0x003A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_Deployable_GenericExplosives_C*     K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives; // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x004A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Phone_Detonator_C_ExplosivesReady) == 0x000008, "Wrong alignment on BP_Phone_Detonator_C_ExplosivesReady");
static_assert(sizeof(BP_Phone_Detonator_C_ExplosivesReady) == 0x000050, "Wrong size on BP_Phone_Detonator_C_ExplosivesReady");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, ExplosivesClass) == 0x000000, "Member 'BP_Phone_Detonator_C_ExplosivesReady::ExplosivesClass' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, Valid) == 0x000008, "Member 'BP_Phone_Detonator_C_ExplosivesReady::Valid' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, Temp_int_Variable) == 0x00000C, "Member 'BP_Phone_Detonator_C_ExplosivesReady::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_Add_IntInt_ReturnValue) == 0x000010, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_IsValid_ReturnValue) == 0x000014, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_GetPlacedDeployableItemsCount_ReturnValue) == 0x000018, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_GetPlacedDeployableItemsCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_Greater_IntInt_ReturnValue) == 0x00001C, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_Subtract_IntInt_ReturnValue) == 0x000020, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_LessEqual_IntInt_ReturnValue) == 0x000024, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_GetPlacedDeployableAt_ReturnValue) == 0x000028, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_GetPlacedDeployableAt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_GetObjectClass_ReturnValue) == 0x000030, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_GetObjectClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_IsValid_ReturnValue_1) == 0x000038, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_EqualEqual_ClassClass_ReturnValue) == 0x000039, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_EqualEqual_ClassClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives) == 0x000040, "Member 'BP_Phone_Detonator_C_ExplosivesReady::K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'BP_Phone_Detonator_C_ExplosivesReady::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_Not_PreBool_ReturnValue) == 0x000049, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_ExplosivesReady, CallFunc_BooleanAND_ReturnValue) == 0x00004A, "Member 'BP_Phone_Detonator_C_ExplosivesReady::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

// Function BP_Phone_Detonator.BP_Phone_Detonator_C.InitiateExplosives
// 0x0050 (0x0050 - 0x0000)
struct BP_Phone_Detonator_C_InitiateExplosives final
{
public:
	class ASQPlayerState*                         PlayerState;                                       // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Explosives_Class;                                  // 0x0008(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Detonation_Delay;                                  // 0x0010(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_GetPlacedDeployableItemsCount_ReturnValue; // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Variable;                                 // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Greater_IntInt_ReturnValue;               // 0x001C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4C02[0x3];                                     // 0x001D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0024(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4C03[0x3];                                     // 0x0025(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x002C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4C04[0x3];                                     // 0x002D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQDeployable*                          CallFunc_GetPlacedDeployableAt_ReturnValue;        // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 CallFunc_GetObjectClass_ReturnValue;               // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_Deployable_GenericExplosives_C*     K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives; // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_ClassClass_ReturnValue;        // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x004A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x004B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanAND_ReturnValue;                   // 0x004C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_Phone_Detonator_C_InitiateExplosives) == 0x000008, "Wrong alignment on BP_Phone_Detonator_C_InitiateExplosives");
static_assert(sizeof(BP_Phone_Detonator_C_InitiateExplosives) == 0x000050, "Wrong size on BP_Phone_Detonator_C_InitiateExplosives");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, PlayerState) == 0x000000, "Member 'BP_Phone_Detonator_C_InitiateExplosives::PlayerState' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, Explosives_Class) == 0x000008, "Member 'BP_Phone_Detonator_C_InitiateExplosives::Explosives_Class' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, Detonation_Delay) == 0x000010, "Member 'BP_Phone_Detonator_C_InitiateExplosives::Detonation_Delay' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_GetPlacedDeployableItemsCount_ReturnValue) == 0x000014, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_GetPlacedDeployableItemsCount_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, Temp_int_Variable) == 0x000018, "Member 'BP_Phone_Detonator_C_InitiateExplosives::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_Greater_IntInt_ReturnValue) == 0x00001C, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_Greater_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_Add_IntInt_ReturnValue) == 0x000020, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_Less_IntInt_ReturnValue) == 0x000024, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_Subtract_IntInt_ReturnValue) == 0x000028, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_LessEqual_IntInt_ReturnValue) == 0x00002C, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_GetPlacedDeployableAt_ReturnValue) == 0x000030, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_GetPlacedDeployableAt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_GetObjectClass_ReturnValue) == 0x000038, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_GetObjectClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives) == 0x000040, "Member 'BP_Phone_Detonator_C_InitiateExplosives::K2Node_DynamicCast_AsBP_Deployable_Generic_Explosives' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'BP_Phone_Detonator_C_InitiateExplosives::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_EqualEqual_ClassClass_ReturnValue) == 0x000049, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_EqualEqual_ClassClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_Not_PreBool_ReturnValue) == 0x00004A, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_IsValid_ReturnValue) == 0x00004B, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_Phone_Detonator_C_InitiateExplosives, CallFunc_BooleanAND_ReturnValue) == 0x00004C, "Member 'BP_Phone_Detonator_C_InitiateExplosives::CallFunc_BooleanAND_ReturnValue' has a wrong offset!");

}
