#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_WeaponPreview

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "UMG_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_WeaponPreview.W_WeaponPreview_C.OnRoleSet__DelegateSignature
// 0x0008 (0x0008 - 0x0000)
struct W_WeaponPreview_C_OnRoleSet__DelegateSignature final
{
public:
	class USQRoleSettings*                        RoleReference;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_WeaponPreview_C_OnRoleSet__DelegateSignature) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnRoleSet__DelegateSignature");
static_assert(sizeof(W_WeaponPreview_C_OnRoleSet__DelegateSignature) == 0x000008, "Wrong size on W_WeaponPreview_C_OnRoleSet__DelegateSignature");
static_assert(offsetof(W_WeaponPreview_C_OnRoleSet__DelegateSignature, RoleReference) == 0x000000, "Member 'W_WeaponPreview_C_OnRoleSet__DelegateSignature::RoleReference' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.ExecuteUbergraph_W_WeaponPreview
// 0x00C0 (0x00C0 - 0x0000)
struct W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B3[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQRoleSettings*                        K2Node_CustomEvent_New_Role;                       // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0021(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B4[0x2];                                     // 0x0022(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         K2Node_CustomEvent_New_Rotation_Z__Yaw_;           // 0x0024(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x0028(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FHitResult                             CallFunc_K2_SetRelativeRotation_SweepHitResult;    // 0x0034(0x0088)(IsPlainOldData, NoDestructor, ContainsInstancedReference)
};
static_assert(alignof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview) == 0x000008, "Wrong alignment on W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview");
static_assert(sizeof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview) == 0x0000C0, "Wrong size on W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, EntryPoint) == 0x000000, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, CallFunc_IsValid_ReturnValue) == 0x000004, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, CallFunc_GetOwningPlayer_ReturnValue) == 0x000008, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, K2Node_CustomEvent_New_Role) == 0x000010, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::K2Node_CustomEvent_New_Role' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000018, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, K2Node_DynamicCast_bSuccess) == 0x000020, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, CallFunc_IsValid_ReturnValue_1) == 0x000021, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, K2Node_CustomEvent_New_Rotation_Z__Yaw_) == 0x000024, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::K2Node_CustomEvent_New_Rotation_Z__Yaw_' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, CallFunc_MakeRotator_ReturnValue) == 0x000028, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview, CallFunc_K2_SetRelativeRotation_SweepHitResult) == 0x000034, "Member 'W_WeaponPreview_C_ExecuteUbergraph_W_WeaponPreview::CallFunc_K2_SetRelativeRotation_SweepHitResult' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.SetZRotation
// 0x0004 (0x0004 - 0x0000)
struct W_WeaponPreview_C_SetZRotation final
{
public:
	float                                         New_Rotation_Z__Yaw_;                              // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_WeaponPreview_C_SetZRotation) == 0x000004, "Wrong alignment on W_WeaponPreview_C_SetZRotation");
static_assert(sizeof(W_WeaponPreview_C_SetZRotation) == 0x000004, "Wrong size on W_WeaponPreview_C_SetZRotation");
static_assert(offsetof(W_WeaponPreview_C_SetZRotation, New_Rotation_Z__Yaw_) == 0x000000, "Member 'W_WeaponPreview_C_SetZRotation::New_Rotation_Z__Yaw_' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.Set Role
// 0x0008 (0x0008 - 0x0000)
struct W_WeaponPreview_C_Set_Role final
{
public:
	class USQRoleSettings*                        New_Role;                                          // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_WeaponPreview_C_Set_Role) == 0x000008, "Wrong alignment on W_WeaponPreview_C_Set_Role");
static_assert(sizeof(W_WeaponPreview_C_Set_Role) == 0x000008, "Wrong size on W_WeaponPreview_C_Set_Role");
static_assert(offsetof(W_WeaponPreview_C_Set_Role, New_Role) == 0x000000, "Member 'W_WeaponPreview_C_Set_Role::New_Role' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.CreateWeaponPreview
// 0x00B0 (0x00B0 - 0x0000)
struct W_WeaponPreview_C_CreateWeaponPreview final
{
public:
	TSoftClassPtr<class UClass>                   WeaponToDisplay;                                   // 0x0000(0x0028)(BlueprintVisible, BlueprintReadOnly, Parm, UObjectWrapper, HasGetValueTypeHash)
	TSoftObjectPtr<class USQItemSkinCollection>   SkinToDisplay;                                     // 0x0028(0x0028)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
	class UBP_SQRoleSettings_C*                   RoleSettings;                                      // 0x0050(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32B5[0x8];                                     // 0x0058(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTransform                             CallFunc_MakeTransform_ReturnValue;                // 0x0060(0x0030)(IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0090(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B6[0x7];                                     // 0x0091(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AActor*                                 CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue; // 0x0098(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_R2T_Weapon_C*                       CallFunc_FinishSpawningActor_ReturnValue;          // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               CallFunc_GetDynamicMaterial_ReturnValue;           // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_WeaponPreview_C_CreateWeaponPreview) == 0x000010, "Wrong alignment on W_WeaponPreview_C_CreateWeaponPreview");
static_assert(sizeof(W_WeaponPreview_C_CreateWeaponPreview) == 0x0000B0, "Wrong size on W_WeaponPreview_C_CreateWeaponPreview");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, WeaponToDisplay) == 0x000000, "Member 'W_WeaponPreview_C_CreateWeaponPreview::WeaponToDisplay' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, SkinToDisplay) == 0x000028, "Member 'W_WeaponPreview_C_CreateWeaponPreview::SkinToDisplay' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, RoleSettings) == 0x000050, "Member 'W_WeaponPreview_C_CreateWeaponPreview::RoleSettings' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, CallFunc_MakeTransform_ReturnValue) == 0x000060, "Member 'W_WeaponPreview_C_CreateWeaponPreview::CallFunc_MakeTransform_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, CallFunc_IsValid_ReturnValue) == 0x000090, "Member 'W_WeaponPreview_C_CreateWeaponPreview::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue) == 0x000098, "Member 'W_WeaponPreview_C_CreateWeaponPreview::CallFunc_BeginDeferredActorSpawnFromClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, CallFunc_FinishSpawningActor_ReturnValue) == 0x0000A0, "Member 'W_WeaponPreview_C_CreateWeaponPreview::CallFunc_FinishSpawningActor_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_CreateWeaponPreview, CallFunc_GetDynamicMaterial_ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_CreateWeaponPreview::CallFunc_GetDynamicMaterial_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseMove
// 0x0308 (0x0308 - 0x0000)
struct W_WeaponPreview_C_OnMouseMove final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	bool                                          Temp_bool_Variable;                                // 0x0160(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B7[0x3];                                     // 0x0161(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Temp_float_Variable;                               // 0x0164(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_PointerEvent_GetCursorDelta_ReturnValue;  // 0x0168(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X;                          // 0x0170(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x0174(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0178(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_FloatFloat_ReturnValue;          // 0x0179(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_NotEqual_FloatFloat_ReturnValue_1;        // 0x017A(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_BooleanOR_ReturnValue;                    // 0x017B(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector2D                              CallFunc_PointerEvent_GetCursorDelta_ReturnValue_1; // 0x017C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X_1;                        // 0x0184(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y_1;                        // 0x0188(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x018C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_1;        // 0x0190(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_Select_Default;                             // 0x0194(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0198(0x00B8)()
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0250(0x00B8)()
};
static_assert(alignof(W_WeaponPreview_C_OnMouseMove) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseMove");
static_assert(sizeof(W_WeaponPreview_C_OnMouseMove) == 0x000308, "Wrong size on W_WeaponPreview_C_OnMouseMove");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, MyGeometry) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseMove::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, MouseEvent) == 0x000038, "Member 'W_WeaponPreview_C_OnMouseMove::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_OnMouseMove::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, Temp_bool_Variable) == 0x000160, "Member 'W_WeaponPreview_C_OnMouseMove::Temp_bool_Variable' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, Temp_float_Variable) == 0x000164, "Member 'W_WeaponPreview_C_OnMouseMove::Temp_float_Variable' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_PointerEvent_GetCursorDelta_ReturnValue) == 0x000168, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_PointerEvent_GetCursorDelta_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_BreakVector2D_X) == 0x000170, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_BreakVector2D_Y) == 0x000174, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_IsValid_ReturnValue) == 0x000178, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_NotEqual_FloatFloat_ReturnValue) == 0x000179, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_NotEqual_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_NotEqual_FloatFloat_ReturnValue_1) == 0x00017A, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_NotEqual_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_BooleanOR_ReturnValue) == 0x00017B, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_BooleanOR_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_PointerEvent_GetCursorDelta_ReturnValue_1) == 0x00017C, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_PointerEvent_GetCursorDelta_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_BreakVector2D_X_1) == 0x000184, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_BreakVector2D_X_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_BreakVector2D_Y_1) == 0x000188, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_BreakVector2D_Y_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00018C, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_Multiply_FloatFloat_ReturnValue_1) == 0x000190, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_Multiply_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, K2Node_Select_Default) == 0x000194, "Member 'W_WeaponPreview_C_OnMouseMove::K2Node_Select_Default' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_Handled_ReturnValue) == 0x000198, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_Handled_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseMove, CallFunc_Unhandled_ReturnValue) == 0x000250, "Member 'W_WeaponPreview_C_OnMouseMove::CallFunc_Unhandled_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseButtonDown
// 0x0220 (0x0220 - 0x0000)
struct W_WeaponPreview_C_OnMouseButtonDown final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	bool                                          CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue; // 0x0160(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B8[0x7];                                     // 0x0161(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0168(0x00B8)()
};
static_assert(alignof(W_WeaponPreview_C_OnMouseButtonDown) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseButtonDown");
static_assert(sizeof(W_WeaponPreview_C_OnMouseButtonDown) == 0x000220, "Wrong size on W_WeaponPreview_C_OnMouseButtonDown");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonDown, MyGeometry) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseButtonDown::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonDown, MouseEvent) == 0x000038, "Member 'W_WeaponPreview_C_OnMouseButtonDown::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonDown, ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_OnMouseButtonDown::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonDown, CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue) == 0x000160, "Member 'W_WeaponPreview_C_OnMouseButtonDown::CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonDown, CallFunc_Handled_ReturnValue) == 0x000168, "Member 'W_WeaponPreview_C_OnMouseButtonDown::CallFunc_Handled_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseButtonUp
// 0x0220 (0x0220 - 0x0000)
struct W_WeaponPreview_C_OnMouseButtonUp final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	bool                                          CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue; // 0x0160(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_32B9[0x7];                                     // 0x0161(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0168(0x00B8)()
};
static_assert(alignof(W_WeaponPreview_C_OnMouseButtonUp) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseButtonUp");
static_assert(sizeof(W_WeaponPreview_C_OnMouseButtonUp) == 0x000220, "Wrong size on W_WeaponPreview_C_OnMouseButtonUp");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonUp, MyGeometry) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseButtonUp::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonUp, MouseEvent) == 0x000038, "Member 'W_WeaponPreview_C_OnMouseButtonUp::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonUp, ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_OnMouseButtonUp::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonUp, CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue) == 0x000160, "Member 'W_WeaponPreview_C_OnMouseButtonUp::CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseButtonUp, CallFunc_Handled_ReturnValue) == 0x000168, "Member 'W_WeaponPreview_C_OnMouseButtonUp::CallFunc_Handled_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseWheel
// 0x02D8 (0x02D8 - 0x0000)
struct W_WeaponPreview_C_OnMouseWheel final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	struct FEventReply                            ReturnValue;                                       // 0x00A8(0x00B8)(Parm, OutParm, ReturnParm)
	float                                         CallFunc_PointerEvent_GetWheelDelta_ReturnValue;   // 0x0160(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_32BA[0x4];                                     // 0x0164(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FEventReply                            CallFunc_Unhandled_ReturnValue;                    // 0x0168(0x00B8)()
	struct FEventReply                            CallFunc_Handled_ReturnValue;                      // 0x0220(0x00B8)()
};
static_assert(alignof(W_WeaponPreview_C_OnMouseWheel) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseWheel");
static_assert(sizeof(W_WeaponPreview_C_OnMouseWheel) == 0x0002D8, "Wrong size on W_WeaponPreview_C_OnMouseWheel");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, MyGeometry) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseWheel::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, MouseEvent) == 0x000038, "Member 'W_WeaponPreview_C_OnMouseWheel::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_OnMouseWheel::ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, CallFunc_PointerEvent_GetWheelDelta_ReturnValue) == 0x000160, "Member 'W_WeaponPreview_C_OnMouseWheel::CallFunc_PointerEvent_GetWheelDelta_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, CallFunc_Unhandled_ReturnValue) == 0x000168, "Member 'W_WeaponPreview_C_OnMouseWheel::CallFunc_Unhandled_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseWheel, CallFunc_Handled_ReturnValue) == 0x000220, "Member 'W_WeaponPreview_C_OnMouseWheel::CallFunc_Handled_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseEnter
// 0x00B0 (0x00B0 - 0x0000)
struct W_WeaponPreview_C_OnMouseEnter final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	struct FPointerEvent                          MouseEvent;                                        // 0x0038(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	bool                                          CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue; // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x00A9(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_WeaponPreview_C_OnMouseEnter) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseEnter");
static_assert(sizeof(W_WeaponPreview_C_OnMouseEnter) == 0x0000B0, "Wrong size on W_WeaponPreview_C_OnMouseEnter");
static_assert(offsetof(W_WeaponPreview_C_OnMouseEnter, MyGeometry) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseEnter::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseEnter, MouseEvent) == 0x000038, "Member 'W_WeaponPreview_C_OnMouseEnter::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseEnter, CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue) == 0x0000A8, "Member 'W_WeaponPreview_C_OnMouseEnter::CallFunc_PointerEvent_IsMouseButtonDown_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseEnter, CallFunc_IsValid_ReturnValue) == 0x0000A9, "Member 'W_WeaponPreview_C_OnMouseEnter::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function W_WeaponPreview.W_WeaponPreview_C.OnMouseLeave
// 0x0078 (0x0078 - 0x0000)
struct W_WeaponPreview_C_OnMouseLeave final
{
public:
	struct FPointerEvent                          MouseEvent;                                        // 0x0000(0x0070)(ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_WeaponPreview_C_OnMouseLeave) == 0x000008, "Wrong alignment on W_WeaponPreview_C_OnMouseLeave");
static_assert(sizeof(W_WeaponPreview_C_OnMouseLeave) == 0x000078, "Wrong size on W_WeaponPreview_C_OnMouseLeave");
static_assert(offsetof(W_WeaponPreview_C_OnMouseLeave, MouseEvent) == 0x000000, "Member 'W_WeaponPreview_C_OnMouseLeave::MouseEvent' has a wrong offset!");
static_assert(offsetof(W_WeaponPreview_C_OnMouseLeave, CallFunc_IsValid_ReturnValue) == 0x000070, "Member 'W_WeaponPreview_C_OnMouseLeave::CallFunc_IsValid_ReturnValue' has a wrong offset!");

}
