#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericVehicleOpenTurret

#include "Basic.hpp"

#include "InputCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.ExecuteUbergraph_BP_GenericVehicleOpenTurret
// 0x0170 (0x0170 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_37BC[0x4];                                     // 0x0004(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_1;                     // 0x0008(0x0018)(HasGetValueTypeHash)
	struct FKey                                   K2Node_InputActionEvent_Key;                       // 0x0020(0x0018)(HasGetValueTypeHash)
	struct FKey                                   Temp_struct_Variable;                              // 0x0038(0x0018)(HasGetValueTypeHash)
	class USQVehicleInventoryComponent*           CallFunc_GetVehicleInventory_ReturnValue;          // 0x0050(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_InputAxisEvent_AxisValue_3;                 // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_InputAxisEvent_AxisValue_2;                 // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue;                  // 0x0060(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue_1;                // 0x006C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCurrentWeaponInputEnabled_ReturnValue;  // 0x0078(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_1; // 0x0079(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37BD[0x6];                                     // 0x007A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class USQGameUserSettings*                    CallFunc_GetSquadGameUserSettings_ReturnValue;     // 0x0080(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_InputAxisEvent_AxisValue_1;                 // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         K2Node_InputAxisEvent_AxisValue;                   // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_1;        // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_2; // 0x0098(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37BE[0x3];                                     // 0x0099(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue;         // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQWeapon*                              K2Node_DynamicCast_AsSQWeapon;                     // 0x00A0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x00A8(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37BF[0x3];                                     // 0x00A9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_Lerp_ReturnValue;                         // 0x00AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsZoomed_ReturnValue;                     // 0x00B0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37C0[0x7];                                     // 0x00B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   Temp_struct_Variable_1;                            // 0x00B8(0x0018)(HasGetValueTypeHash)
	struct FKey                                   K2Node_InputActionEvent_Key_2;                     // 0x00D0(0x0018)(HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_2;        // 0x00E8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue_1;       // 0x00EC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_3;        // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_4;        // 0x00F4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue_2;                // 0x00F8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_5;        // 0x0104(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue_3;                // 0x0108(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_3; // 0x0114(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37C1[0x3];                                     // 0x0115(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FKey                                   K2Node_InputActionEvent_Key_3;                     // 0x0118(0x0018)(HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue_2;       // 0x0130(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_6;        // 0x0134(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue_4;                // 0x0138(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37C2[0x4];                                     // 0x0144(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQWeapon*                              K2Node_DynamicCast_AsSQWeapon_1;                   // 0x0148(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0150(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsZoomed_ReturnValue_1;                   // 0x0151(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_37C3[0x2];                                     // 0x0152(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue_3;       // 0x0154(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_7;        // 0x0158(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_8;        // 0x015C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_MakeRotator_ReturnValue_5;                // 0x0160(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret) == 0x000170, "Wrong size on BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, EntryPoint) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::EntryPoint' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputActionEvent_Key_1) == 0x000008, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputActionEvent_Key_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputActionEvent_Key) == 0x000020, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputActionEvent_Key' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, Temp_struct_Variable) == 0x000038, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::Temp_struct_Variable' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetVehicleInventory_ReturnValue) == 0x000050, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetVehicleInventory_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputAxisEvent_AxisValue_3) == 0x000058, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputAxisEvent_AxisValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputAxisEvent_AxisValue_2) == 0x00005C, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputAxisEvent_AxisValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue) == 0x000060, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue_1) == 0x00006C, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsCurrentWeaponInputEnabled_ReturnValue) == 0x000078, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsCurrentWeaponInputEnabled_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_1) == 0x000079, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetSquadGameUserSettings_ReturnValue) == 0x000080, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetSquadGameUserSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x000088, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputAxisEvent_AxisValue_1) == 0x00008C, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputAxisEvent_AxisValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputAxisEvent_AxisValue) == 0x000090, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputAxisEvent_AxisValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_1) == 0x000094, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_2) == 0x000098, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetWorldDeltaSeconds_ReturnValue) == 0x00009C, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetWorldDeltaSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_DynamicCast_AsSQWeapon) == 0x0000A0, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_DynamicCast_AsSQWeapon' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_DynamicCast_bSuccess) == 0x0000A8, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Lerp_ReturnValue) == 0x0000AC, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Lerp_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsZoomed_ReturnValue) == 0x0000B0, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsZoomed_ReturnValue' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, Temp_struct_Variable_1) == 0x0000B8, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::Temp_struct_Variable_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputActionEvent_Key_2) == 0x0000D0, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputActionEvent_Key_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_2) == 0x0000E8, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetWorldDeltaSeconds_ReturnValue_1) == 0x0000EC, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetWorldDeltaSeconds_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_3) == 0x0000F0, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_4) == 0x0000F4, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue_2) == 0x0000F8, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_5) == 0x000104, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue_3) == 0x000108, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_3) == 0x000114, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsCurrentWeaponInputEnabled_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_InputActionEvent_Key_3) == 0x000118, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_InputActionEvent_Key_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetWorldDeltaSeconds_ReturnValue_2) == 0x000130, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetWorldDeltaSeconds_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_6) == 0x000134, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_6' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue_4) == 0x000138, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_DynamicCast_AsSQWeapon_1) == 0x000148, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_DynamicCast_AsSQWeapon_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, K2Node_DynamicCast_bSuccess_1) == 0x000150, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_IsZoomed_ReturnValue_1) == 0x000151, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_IsZoomed_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_GetWorldDeltaSeconds_ReturnValue_3) == 0x000154, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_GetWorldDeltaSeconds_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_7) == 0x000158, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_7' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_Multiply_FloatFloat_ReturnValue_8) == 0x00015C, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_Multiply_FloatFloat_ReturnValue_8' has a wrong offset!");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret, CallFunc_MakeRotator_ReturnValue_5) == 0x000160, "Member 'BP_GenericVehicleOpenTurret_C_ExecuteUbergraph_BP_GenericVehicleOpenTurret::CallFunc_MakeRotator_ReturnValue_5' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2
// 0x0004 (0x0004 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2 final
{
public:
	float                                         AxisValue;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2) == 0x000004, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2) == 0x000004, "Wrong size on BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2, AxisValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveForward_K2Node_InputAxisEvent_2::AxisValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0
// 0x0004 (0x0004 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0 final
{
public:
	float                                         AxisValue;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0) == 0x000004, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0) == 0x000004, "Wrong size on BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0, AxisValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpAxisEvt_VehicleMoveRight_K2Node_InputAxisEvent_0::AxisValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpAxisEvt_LookUp_K2Node_InputAxisEvent_42
// 0x0004 (0x0004 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42 final
{
public:
	float                                         AxisValue;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42) == 0x000004, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42) == 0x000004, "Wrong size on BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42, AxisValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpAxisEvt_LookUp_K2Node_InputAxisEvent_42::AxisValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpAxisEvt_Turn_K2Node_InputAxisEvent_39
// 0x0004 (0x0004 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39 final
{
public:
	float                                         AxisValue;                                         // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39) == 0x000004, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39) == 0x000004, "Wrong size on BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39, AxisValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpAxisEvt_Turn_K2Node_InputAxisEvent_39::AxisValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpActEvt_Fire_K2Node_InputActionEvent_0
// 0x0018 (0x0018 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0) == 0x000018, "Wrong size on BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0, Key) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_0::Key' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpActEvt_Fire_K2Node_InputActionEvent_1
// 0x0018 (0x0018 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1) == 0x000018, "Wrong size on BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1, Key) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpActEvt_Fire_K2Node_InputActionEvent_1::Key' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpActEvt_Focus_K2Node_InputActionEvent_2
// 0x0018 (0x0018 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2) == 0x000018, "Wrong size on BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2, Key) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_2::Key' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.InpActEvt_Focus_K2Node_InputActionEvent_3
// 0x0018 (0x0018 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3 final
{
public:
	struct FKey                                   Key;                                               // 0x0000(0x0018)(BlueprintVisible, BlueprintReadOnly, Parm, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3) == 0x000018, "Wrong size on BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3, Key) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_InpActEvt_Focus_K2Node_InputActionEvent_3::Key' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.Get3PAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_Get3PAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_Get3PAttachComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_Get3PAttachComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_Get3PAttachComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_Get3PAttachComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_Get3PAttachComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_Get3PAttachComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.Get1PAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_Get1PAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_Get1PAttachComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_Get1PAttachComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_Get1PAttachComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_Get1PAttachComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_Get1PAttachComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_Get1PAttachComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.GetMasterPoseComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent final
{
public:
	class USkinnedMeshComponent*                  ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_GetMasterPoseComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.GetWeaponAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_GetWeaponAttachComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.GetDefaultCameraLocationComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_GetDefaultCameraLocationComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.GetADSCameraLocationComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_GetADSCameraLocationComponent::ReturnValue' has a wrong offset!");

// Function BP_GenericVehicleOpenTurret.BP_GenericVehicleOpenTurret_C.GetSoldierAttachComponent
// 0x0008 (0x0008 - 0x0000)
struct BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent final
{
public:
	class USceneComponent*                        ReturnValue;                                       // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent) == 0x000008, "Wrong alignment on BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent");
static_assert(sizeof(BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent) == 0x000008, "Wrong size on BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent");
static_assert(offsetof(BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent, ReturnValue) == 0x000000, "Member 'BP_GenericVehicleOpenTurret_C_GetSoldierAttachComponent::ReturnValue' has a wrong offset!");

}
