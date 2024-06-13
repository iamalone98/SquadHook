#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SmokeGenerator_Tracked

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function SmokeGenerator_Tracked.SmokeGenerator_Tracked_C.ExecuteUbergraph_SmokeGenerator_Tracked
// 0x0138 (0x0138 - 0x0000)
struct SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0004(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x000C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable_1;                   // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable_1;                  // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue_1;                 // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x001C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	class AActor*                                 K2Node_Event_OwnerActor;                           // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQGroundVehicle*                       K2Node_DynamicCast_AsSQGround_Vehicle;             // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4D05[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class FName>                           CallFunc_GetAllSocketNames_ReturnValue;            // 0x0040(0x0010)(ReferenceParm)
	class ASQLastingEffect*                       CallFunc_Array_Get_Item;                           // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FName                                   CallFunc_Array_Get_Item_1;                         // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_GetSocketLocation_ReturnValue;            // 0x0060(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4D06[0x4];                                     // 0x006C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 CallFunc_Conv_NameToString_ReturnValue;            // 0x0070(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class ASQLastingEffect*                       CallFunc_SpawnLastingEffect_ReturnValue;           // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Contains_ReturnValue;                     // 0x0088(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4D07[0x7];                                     // 0x0089(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USceneComponent*                        CallFunc_K2_GetRootComponent_ReturnValue;          // 0x0090(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FHitResult                             CallFunc_K2_SetWorldLocation_SweepHitResult;       // 0x0098(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          CallFunc_K2_AttachToComponent_ReturnValue;         // 0x0120(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4D08[0x3];                                     // 0x0121(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Array_Add_ReturnValue;                    // 0x0124(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0128(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue_1;               // 0x012C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0130(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Less_IntInt_ReturnValue_1;                // 0x0131(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked) == 0x000008, "Wrong alignment on SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked");
static_assert(sizeof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked) == 0x000138, "Wrong size on SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, EntryPoint) == 0x000000, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::EntryPoint' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, Temp_int_Loop_Counter_Variable) == 0x000004, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Add_IntInt_ReturnValue) == 0x000008, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, Temp_int_Array_Index_Variable) == 0x00000C, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, Temp_int_Array_Index_Variable_1) == 0x000010, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::Temp_int_Array_Index_Variable_1' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, Temp_int_Loop_Counter_Variable_1) == 0x000014, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::Temp_int_Loop_Counter_Variable_1' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Add_IntInt_ReturnValue_1) == 0x000018, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Add_IntInt_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_MakeRotator_ReturnValue) == 0x00001C, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, K2Node_Event_OwnerActor) == 0x000028, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::K2Node_Event_OwnerActor' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, K2Node_DynamicCast_AsSQGround_Vehicle) == 0x000030, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::K2Node_DynamicCast_AsSQGround_Vehicle' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_GetAllSocketNames_ReturnValue) == 0x000040, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_GetAllSocketNames_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Array_Get_Item) == 0x000050, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Array_Get_Item_1) == 0x000058, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_GetSocketLocation_ReturnValue) == 0x000060, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_GetSocketLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Conv_NameToString_ReturnValue) == 0x000070, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Conv_NameToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_SpawnLastingEffect_ReturnValue) == 0x000080, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_SpawnLastingEffect_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Contains_ReturnValue) == 0x000088, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Contains_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_K2_GetRootComponent_ReturnValue) == 0x000090, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_K2_GetRootComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_K2_SetWorldLocation_SweepHitResult) == 0x000098, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_K2_SetWorldLocation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_K2_AttachToComponent_ReturnValue) == 0x000120, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_K2_AttachToComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Array_Add_ReturnValue) == 0x000124, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Array_Add_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Array_Length_ReturnValue) == 0x000128, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Array_Length_ReturnValue_1) == 0x00012C, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Array_Length_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Less_IntInt_ReturnValue) == 0x000130, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked, CallFunc_Less_IntInt_ReturnValue_1) == 0x000131, "Member 'SmokeGenerator_Tracked_C_ExecuteUbergraph_SmokeGenerator_Tracked::CallFunc_Less_IntInt_ReturnValue_1' has a wrong offset!");

// Function SmokeGenerator_Tracked.SmokeGenerator_Tracked_C.SetupParticleSystem
// 0x0008 (0x0008 - 0x0000)
struct SmokeGenerator_Tracked_C_SetupParticleSystem final
{
public:
	class AActor*                                 OwnerActor;                                        // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(SmokeGenerator_Tracked_C_SetupParticleSystem) == 0x000008, "Wrong alignment on SmokeGenerator_Tracked_C_SetupParticleSystem");
static_assert(sizeof(SmokeGenerator_Tracked_C_SetupParticleSystem) == 0x000008, "Wrong size on SmokeGenerator_Tracked_C_SetupParticleSystem");
static_assert(offsetof(SmokeGenerator_Tracked_C_SetupParticleSystem, OwnerActor) == 0x000000, "Member 'SmokeGenerator_Tracked_C_SetupParticleSystem::OwnerActor' has a wrong offset!");

}

