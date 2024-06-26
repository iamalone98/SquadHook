#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnableGhost

#include "Basic.hpp"

#include "InputCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.ExecuteUbergraph_BP_SpawnableGhost
// 0x0170 (0x0170 - 0x0000)
struct BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2F9F[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_2;                     // 0x0008(0x0018)(HasGetValueTypeHash)
	struct FKey                                   Temp_struct_Variable;                              // 0x0020(0x0018)(HasGetValueTypeHash)
	struct FKey                                   K2Node_InputActionEvent_Key_1;                     // 0x0038(0x0018)(HasGetValueTypeHash)
	struct FKey                                   K2Node_InputActionEvent_Key;                       // 0x0050(0x0018)(HasGetValueTypeHash)
	struct FKey                                   Temp_struct_Variable_1;                            // 0x0068(0x0018)(HasGetValueTypeHash)
	TDelegate<void(class AActor* DestroyedActor)> K2Node_CreateDelegate_OutputDelegate;              // 0x0080(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          CallFunc_K2_IsTimerActiveHandle_ReturnValue;       // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_IsValidTimerHandle_ReturnValue;        // 0x0091(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FA0[0x6];                                     // 0x0092(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_3;                     // 0x0098(0x0018)(HasGetValueTypeHash)
	struct FHitResult                             CallFunc_K2_AddActorWorldRotation_SweepHitResult;  // 0x00B0(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
	bool                                          CallFunc_EqualEqual_RotatorRotator_ReturnValue;    // 0x0138(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_EqualEqual_RotatorRotator_ReturnValue_1;  // 0x0139(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_IsTimerActiveHandle_ReturnValue_1;     // 0x013A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FA1[0x1];                                     // 0x013B(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x013C(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2FA2[0x4];                                     // 0x014C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0150(0x0008)(NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue;          // 0x0158(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AActor*                                 K2Node_CustomEvent_DestroyedActor;                 // 0x0160(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue_1;        // 0x0168(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost");
static_assert(sizeof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost) == 0x000170, "Wrong size on BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, EntryPoint) == 0x000000, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_InputActionEvent_Key_2) == 0x000008, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_InputActionEvent_Key_2' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, Temp_struct_Variable) == 0x000020, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_InputActionEvent_Key_1) == 0x000038, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_InputActionEvent_Key_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_InputActionEvent_Key) == 0x000050, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_InputActionEvent_Key' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, Temp_struct_Variable_1) == 0x000068, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_CreateDelegate_OutputDelegate) == 0x000080, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_K2_IsTimerActiveHandle_ReturnValue) == 0x000090, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_K2_IsTimerActiveHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_K2_IsValidTimerHandle_ReturnValue) == 0x000091, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_K2_IsValidTimerHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_InputActionEvent_Key_3) == 0x000098, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_InputActionEvent_Key_3' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_K2_AddActorWorldRotation_SweepHitResult) == 0x0000B0, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_K2_AddActorWorldRotation_SweepHitResult' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_EqualEqual_RotatorRotator_ReturnValue) == 0x000138, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_EqualEqual_RotatorRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_EqualEqual_RotatorRotator_ReturnValue_1) == 0x000139, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_EqualEqual_RotatorRotator_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_K2_IsTimerActiveHandle_ReturnValue_1) == 0x00013A, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_K2_IsTimerActiveHandle_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_CreateDelegate_OutputDelegate_1) == 0x00013C, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000150, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_GetPlayerController_ReturnValue) == 0x000158, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_GetPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, K2Node_CustomEvent_DestroyedActor) == 0x000160, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::K2Node_CustomEvent_DestroyedActor' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost, CallFunc_GetPlayerController_ReturnValue_1) == 0x000168, "Member 'BP_SpawnableGhost_C_ExecuteUbergraph_BP_SpawnableGhost::CallFunc_GetPlayerController_ReturnValue_1' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.CameraManDestroyed
// 0x0008 (0x0008 - 0x0000)
struct BP_SpawnableGhost_C_CameraManDestroyed final
{
public:
	class AActor*                                 DestroyedActor;                                    // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_CameraManDestroyed) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_CameraManDestroyed");
static_assert(sizeof(BP_SpawnableGhost_C_CameraManDestroyed) == 0x000008, "Wrong size on BP_SpawnableGhost_C_CameraManDestroyed");
static_assert(offsetof(BP_SpawnableGhost_C_CameraManDestroyed, DestroyedActor) == 0x000000, "Member 'BP_SpawnableGhost_C_CameraManDestroyed::DestroyedActor' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0
// 0x0018 (0x0018 - 0x0000)
struct BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0");
static_assert(sizeof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0) == 0x000018, "Wrong size on BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0");
static_assert(offsetof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0, Key) == 0x000000, "Member 'BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_0::Key' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1
// 0x0018 (0x0018 - 0x0000)
struct BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1");
static_assert(sizeof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1) == 0x000018, "Wrong size on BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1");
static_assert(offsetof(BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1, Key) == 0x000000, "Member 'BP_SpawnableGhost_C_InpActEvt_RotateGhostRight_K2Node_InputActionEvent_1::Key' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2
// 0x0018 (0x0018 - 0x0000)
struct BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2");
static_assert(sizeof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2) == 0x000018, "Wrong size on BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2");
static_assert(offsetof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2, Key) == 0x000000, "Member 'BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_2::Key' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3
// 0x0018 (0x0018 - 0x0000)
struct BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3");
static_assert(sizeof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3) == 0x000018, "Wrong size on BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3");
static_assert(offsetof(BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3, Key) == 0x000000, "Member 'BP_SpawnableGhost_C_InpActEvt_RotateGhostLeft_K2Node_InputActionEvent_3::Key' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.IsFullyLoaded
// 0x0001 (0x0001 - 0x0000)
struct BP_SpawnableGhost_C_IsFullyLoaded final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SpawnableGhost_C_IsFullyLoaded) == 0x000001, "Wrong alignment on BP_SpawnableGhost_C_IsFullyLoaded");
static_assert(sizeof(BP_SpawnableGhost_C_IsFullyLoaded) == 0x000001, "Wrong size on BP_SpawnableGhost_C_IsFullyLoaded");
static_assert(offsetof(BP_SpawnableGhost_C_IsFullyLoaded, ReturnValue) == 0x000000, "Member 'BP_SpawnableGhost_C_IsFullyLoaded::ReturnValue' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.ConfirmRequirements
// 0x0001 (0x0001 - 0x0000)
struct BP_SpawnableGhost_C_ConfirmRequirements final
{
public:
	bool                                          ReturnValue;                                       // 0x0000(0x0001)(Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SpawnableGhost_C_ConfirmRequirements) == 0x000001, "Wrong alignment on BP_SpawnableGhost_C_ConfirmRequirements");
static_assert(sizeof(BP_SpawnableGhost_C_ConfirmRequirements) == 0x000001, "Wrong size on BP_SpawnableGhost_C_ConfirmRequirements");
static_assert(offsetof(BP_SpawnableGhost_C_ConfirmRequirements, ReturnValue) == 0x000000, "Member 'BP_SpawnableGhost_C_ConfirmRequirements::ReturnValue' has a wrong offset!");

// Function BP_SpawnableGhost.BP_SpawnableGhost_C.SetUpPreviewMaterial
// 0x0038 (0x0038 - 0x0000)
struct BP_SpawnableGhost_C_SetUpPreviewMaterial final
{
public:
	class UMeshComponent*                         Mesh;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         NumMaterials;                                      // 0x0008(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FA3[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UMaterialInterface*>             CallFunc_GetMaterials_ReturnValue;                 // 0x0010(0x0010)(ReferenceParm)
	int32                                         Temp_int_Variable;                                 // 0x0020(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x0028(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CallFunc_Subtract_IntInt_ReturnValue;              // 0x002C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_LessEqual_IntInt_ReturnValue;             // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_SpawnableGhost_C_SetUpPreviewMaterial) == 0x000008, "Wrong alignment on BP_SpawnableGhost_C_SetUpPreviewMaterial");
static_assert(sizeof(BP_SpawnableGhost_C_SetUpPreviewMaterial) == 0x000038, "Wrong size on BP_SpawnableGhost_C_SetUpPreviewMaterial");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, Mesh) == 0x000000, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::Mesh' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, NumMaterials) == 0x000008, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::NumMaterials' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, CallFunc_GetMaterials_ReturnValue) == 0x000010, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::CallFunc_GetMaterials_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, Temp_int_Variable) == 0x000020, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::Temp_int_Variable' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, CallFunc_Array_Length_ReturnValue) == 0x000024, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, CallFunc_Add_IntInt_ReturnValue) == 0x000028, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, CallFunc_Subtract_IntInt_ReturnValue) == 0x00002C, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::CallFunc_Subtract_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_SpawnableGhost_C_SetUpPreviewMaterial, CallFunc_LessEqual_IntInt_ReturnValue) == 0x000030, "Member 'BP_SpawnableGhost_C_SetUpPreviewMaterial::CallFunc_LessEqual_IntInt_ReturnValue' has a wrong offset!");

}

