#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SoldierPreview

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "SQRoleVersion_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_SoldierPreview.W_SoldierPreview_C.OnRoleSet__DelegateSignature
// 0x0008 (0x0008 - 0x0000)
struct W_SoldierPreview_C_OnRoleSet__DelegateSignature final
{
public:
	class USQRoleSettings*                        RoleReference;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SoldierPreview_C_OnRoleSet__DelegateSignature) == 0x000008, "Wrong alignment on W_SoldierPreview_C_OnRoleSet__DelegateSignature");
static_assert(sizeof(W_SoldierPreview_C_OnRoleSet__DelegateSignature) == 0x000008, "Wrong size on W_SoldierPreview_C_OnRoleSet__DelegateSignature");
static_assert(offsetof(W_SoldierPreview_C_OnRoleSet__DelegateSignature, RoleReference) == 0x000000, "Member 'W_SoldierPreview_C_OnRoleSet__DelegateSignature::RoleReference' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.ExecuteUbergraph_W_SoldierPreview
// 0x00D8 (0x00D8 - 0x0000)
struct W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2D86[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRoleSettings*                        K2Node_CustomEvent_New_Role;                       // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0010(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D87[0x7];                                     // 0x0011(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimMontage*                           K2Node_CustomEvent_NewAnimToPlay;                  // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D88[0x7];                                     // 0x0021(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D89[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_CustomEvent_New_Rotation_Z__Yaw_;           // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x0040(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FHitResult                             CallFunc_K2_SetRelativeRotation_SweepHitResult;    // 0x004C(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview) == 0x000008, "Wrong alignment on W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview");
static_assert(sizeof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview) == 0x0000D8, "Wrong size on W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, EntryPoint) == 0x000000, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, K2Node_CustomEvent_New_Role) == 0x000008, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::K2Node_CustomEvent_New_Role' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, CallFunc_IsValid_ReturnValue) == 0x000010, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, K2Node_CustomEvent_NewAnimToPlay) == 0x000018, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::K2Node_CustomEvent_NewAnimToPlay' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, CallFunc_IsValid_ReturnValue_1) == 0x000020, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, CallFunc_GetOwningPlayer_ReturnValue) == 0x000028, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000030, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, K2Node_CustomEvent_New_Rotation_Z__Yaw_) == 0x00003C, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::K2Node_CustomEvent_New_Rotation_Z__Yaw_' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, CallFunc_MakeRotator_ReturnValue) == 0x000040, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview, CallFunc_K2_SetRelativeRotation_SweepHitResult) == 0x00004C, "Member 'W_SoldierPreview_C_ExecuteUbergraph_W_SoldierPreview::CallFunc_K2_SetRelativeRotation_SweepHitResult' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.SetZRotation
// 0x0004 (0x0004 - 0x0000)
struct W_SoldierPreview_C_SetZRotation final
{
public:
	float                                         New_Rotation_Z__Yaw_;                              // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SoldierPreview_C_SetZRotation) == 0x000004, "Wrong alignment on W_SoldierPreview_C_SetZRotation");
static_assert(sizeof(W_SoldierPreview_C_SetZRotation) == 0x000004, "Wrong size on W_SoldierPreview_C_SetZRotation");
static_assert(offsetof(W_SoldierPreview_C_SetZRotation, New_Rotation_Z__Yaw_) == 0x000000, "Member 'W_SoldierPreview_C_SetZRotation::New_Rotation_Z__Yaw_' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.SetEmoteAnimation
// 0x0008 (0x0008 - 0x0000)
struct W_SoldierPreview_C_SetEmoteAnimation final
{
public:
	class UAnimMontage*                           NewAnimToPlay;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SoldierPreview_C_SetEmoteAnimation) == 0x000008, "Wrong alignment on W_SoldierPreview_C_SetEmoteAnimation");
static_assert(sizeof(W_SoldierPreview_C_SetEmoteAnimation) == 0x000008, "Wrong size on W_SoldierPreview_C_SetEmoteAnimation");
static_assert(offsetof(W_SoldierPreview_C_SetEmoteAnimation, NewAnimToPlay) == 0x000000, "Member 'W_SoldierPreview_C_SetEmoteAnimation::NewAnimToPlay' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.Set Role
// 0x0008 (0x0008 - 0x0000)
struct W_SoldierPreview_C_Set_Role final
{
public:
	class USQRoleSettings*                        New_Role;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SoldierPreview_C_Set_Role) == 0x000008, "Wrong alignment on W_SoldierPreview_C_Set_Role");
static_assert(sizeof(W_SoldierPreview_C_Set_Role) == 0x000008, "Wrong size on W_SoldierPreview_C_Set_Role");
static_assert(offsetof(W_SoldierPreview_C_Set_Role, New_Role) == 0x000000, "Member 'W_SoldierPreview_C_Set_Role::New_Role' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.CreateSoldierPreview
// 0x0070 (0x0070 - 0x0000)
struct W_SoldierPreview_C_CreateSoldierPreview final
{
public:
	class UObject*                                Role;                                              // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_SQRoleSettings_C*                   RoleSettings;                                      // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTransform                             CallFunc_MakeTransform_ReturnValue;                // 0x0010(0x0030)(IsPlainOldData, NoDestructor)
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0048(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0049(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8A[0x6];                                     // 0x004A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue; // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_R2T_Soldier_CustomizeScreen_C*      CallFunc_FinishSpawningActor_ReturnValue;          // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SoldierPreview_C_CreateSoldierPreview) == 0x000010, "Wrong alignment on W_SoldierPreview_C_CreateSoldierPreview");
static_assert(sizeof(W_SoldierPreview_C_CreateSoldierPreview) == 0x000070, "Wrong size on W_SoldierPreview_C_CreateSoldierPreview");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, Role) == 0x000000, "Member 'W_SoldierPreview_C_CreateSoldierPreview::Role' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, RoleSettings) == 0x000008, "Member 'W_SoldierPreview_C_CreateSoldierPreview::RoleSettings' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, CallFunc_MakeTransform_ReturnValue) == 0x000010, "Member 'W_SoldierPreview_C_CreateSoldierPreview::CallFunc_MakeTransform_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x000040, "Member 'W_SoldierPreview_C_CreateSoldierPreview::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, K2Node_DynamicCast_bSuccess) == 0x000048, "Member 'W_SoldierPreview_C_CreateSoldierPreview::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, CallFunc_IsValid_ReturnValue) == 0x000049, "Member 'W_SoldierPreview_C_CreateSoldierPreview::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue) == 0x000050, "Member 'W_SoldierPreview_C_CreateSoldierPreview::CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, CallFunc_FinishSpawningActor_ReturnValue) == 0x000058, "Member 'W_SoldierPreview_C_CreateSoldierPreview::CallFunc_FinishSpawningActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_CreateSoldierPreview, CallFunc_GetDynamicMaterial_ReturnValue) == 0x000060, "Member 'W_SoldierPreview_C_CreateSoldierPreview::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");

// Function W_SoldierPreview.W_SoldierPreview_C.SetupSoldierMesh
// 0x00D8 (0x00D8 - 0x0000)
struct W_SoldierPreview_C_SetupSoldierMesh final
{
public:
	struct FSQInventoryWeaponGroupData            CallFunc_Array_Get_Item;                           // 0x0000(0x0010)()
	struct FSQInventoryData                       CallFunc_Array_Get_Item_1;                         // 0x0010(0x0038)()
	class UClass*                                 CallFunc_LoadClassAsset_Blocking_ReturnValue;      // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_K2_AttachToComponent_ReturnValue;         // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8B[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue;          // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQWeapon*                              K2Node_DynamicCast_AsSQWeapon;                     // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8C[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UBP_SQRoleSettings_C*                   K2Node_DynamicCast_AsBP_SQRole_Settings;           // 0x0070(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2D8D[0x7];                                     // 0x0079(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class USkeletalMeshComponent*                 CallFunc_GetMesh_ReturnValue;                      // 0x0080(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSQRoleVersion                         CallFunc_Array_Get_Item_2;                         // 0x0088(0x0030)(HasGetValueTypeHash)
	class UClass*                                 CallFunc_LoadClassAsset_Blocking_ReturnValue_1;    // 0x00B8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                CallFunc_GetDefaultObjectFor_ReturnValue_1;        // 0x00C0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             K2Node_DynamicCast_AsSQSoldier;                    // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_SoldierPreview_C_SetupSoldierMesh) == 0x000008, "Wrong alignment on W_SoldierPreview_C_SetupSoldierMesh");
static_assert(sizeof(W_SoldierPreview_C_SetupSoldierMesh) == 0x0000D8, "Wrong size on W_SoldierPreview_C_SetupSoldierMesh");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_Array_Get_Item) == 0x000000, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_Array_Get_Item_1) == 0x000010, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_Array_Get_Item_1' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_LoadClassAsset_Blocking_ReturnValue) == 0x000048, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_LoadClassAsset_Blocking_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_K2_AttachToComponent_ReturnValue) == 0x000050, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_K2_AttachToComponent_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_GetDefaultObjectFor_ReturnValue) == 0x000058, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_GetDefaultObjectFor_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_AsSQWeapon) == 0x000060, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_AsSQWeapon' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_bSuccess) == 0x000068, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_AsBP_SQRole_Settings) == 0x000070, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_AsBP_SQRole_Settings' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_bSuccess_1) == 0x000078, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_GetMesh_ReturnValue) == 0x000080, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_GetMesh_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_Array_Get_Item_2) == 0x000088, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_Array_Get_Item_2' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_LoadClassAsset_Blocking_ReturnValue_1) == 0x0000B8, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_LoadClassAsset_Blocking_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, CallFunc_GetDefaultObjectFor_ReturnValue_1) == 0x0000C0, "Member 'W_SoldierPreview_C_SetupSoldierMesh::CallFunc_GetDefaultObjectFor_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_AsSQSoldier) == 0x0000C8, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_AsSQSoldier' has a wrong offset!");
static_assert(offsetof(W_SoldierPreview_C_SetupSoldierMesh, K2Node_DynamicCast_bSuccess_2) == 0x0000D0, "Member 'W_SoldierPreview_C_SetupSoldierMesh::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");

}
