#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_WeaponHandlingIndicator

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function UMG_WeaponHandlingIndicator.UMG_WeaponHandlingIndicator_C.ExecuteUbergraph_UMG_WeaponHandlingIndicator
// 0x01C8 (0x01C8 - 0x0000)
struct UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x0004(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39C4[0x4];                                     // 0x000C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    CallFunc_GetSquadPlayerController_Return_Value;    // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsInVehicle_ReturnValue;                  // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39C5[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  CallFunc_K2_GetPawn_ReturnValue;                   // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39C6[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_MutableSoldier_C*                   K2Node_DynamicCast_AsBP_Mutable_Soldier;           // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39C7[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQEquipableItem*                       CallFunc_GetCurrentWeapon_ReturnValue;             // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ABP_Weapon2_C*                          K2Node_DynamicCast_AsBP_Weapon_2;                  // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39C8[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UAnimInstance*                          CallFunc_GetAnimInstance_ReturnValue;              // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_1P_Upper_C*                         K2Node_DynamicCast_AsBP_1P_Upper;                  // 0x0060(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_2;                     // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39C9[0x3];                                     // 0x0069(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_Conv_RotatorToVector_ReturnValue;         // 0x006C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Conv_RotatorToVector_ReturnValue_1;       // 0x0078(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X;                            // 0x0084(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y;                            // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z;                            // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_1;                          // 0x0090(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_1;                          // 0x0094(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_1;                          // 0x0098(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_1;               // 0x009C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_2;               // 0x00A4(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue;                      // 0x00AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue_1;                    // 0x00B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x00B4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x00B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_1;             // 0x00BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x00C0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue_1;          // 0x00C4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_2;             // 0x00C8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_ComposeRotators_ReturnValue;              // 0x00CC(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector                                CallFunc_Conv_RotatorToVector_ReturnValue_2;       // 0x00D8(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Conv_RotatorToVector_ReturnValue_3;       // 0x00E4(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_2;                          // 0x00F0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_2;                          // 0x00F4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_2;                          // 0x00F8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_3;                          // 0x00FC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_3;                          // 0x0100(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_3;                          // 0x0104(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_3;               // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_4;               // 0x0110(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue_2;                    // 0x0118(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue_3;                    // 0x011C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_4;                          // 0x0120(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_4;                          // 0x0124(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_4;                          // 0x0128(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_Conv_RotatorToVector_ReturnValue_4;       // 0x012C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_5;               // 0x0138(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_X_5;                          // 0x0140(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Y_5;                          // 0x0144(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector_Z_5;                          // 0x0148(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue_4;                    // 0x014C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue_6;               // 0x0150(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetCurrentMOA_ReturnValue;                // 0x0158(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize2D_ReturnValue_5;                    // 0x015C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_3;             // 0x0160(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_1;        // 0x0164(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_2;        // 0x0168(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_4;             // 0x016C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_3;        // 0x0170(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_5;             // 0x0174(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0178(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x01B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_4;        // 0x01B4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_6;             // 0x01B8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue_7;             // 0x01BC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue_5;        // 0x01C0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator) == 0x000008, "Wrong alignment on UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator");
static_assert(sizeof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator) == 0x0001C8, "Wrong size on UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, EntryPoint) == 0x000000, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::EntryPoint' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue) == 0x000004, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_GetSquadPlayerController_Return_Value) == 0x000010, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_GetSquadPlayerController_Return_Value' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_IsInVehicle_ReturnValue) == 0x000018, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_IsInVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_K2_GetPawn_ReturnValue) == 0x000020, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_K2_GetPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_IsValid_ReturnValue) == 0x000028, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_AsBP_Mutable_Soldier) == 0x000030, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_AsBP_Mutable_Soldier' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_GetCurrentWeapon_ReturnValue) == 0x000040, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_GetCurrentWeapon_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_AsBP_Weapon_2) == 0x000048, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_AsBP_Weapon_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_bSuccess_1) == 0x000050, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_GetAnimInstance_ReturnValue) == 0x000058, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_GetAnimInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_AsBP_1P_Upper) == 0x000060, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_AsBP_1P_Upper' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_DynamicCast_bSuccess_2) == 0x000068, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_DynamicCast_bSuccess_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Conv_RotatorToVector_ReturnValue) == 0x00006C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Conv_RotatorToVector_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Conv_RotatorToVector_ReturnValue_1) == 0x000078, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Conv_RotatorToVector_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X) == 0x000084, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y) == 0x000088, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z) == 0x00008C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X_1) == 0x000090, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y_1) == 0x000094, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z_1) == 0x000098, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_1) == 0x00009C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_2) == 0x0000A4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue) == 0x0000AC, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue_1) == 0x0000B0, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue) == 0x0000B4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Divide_FloatFloat_ReturnValue) == 0x0000B8, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_1) == 0x0000BC, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x0000C0, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Divide_FloatFloat_ReturnValue_1) == 0x0000C4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Divide_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_2) == 0x0000C8, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_ComposeRotators_ReturnValue) == 0x0000CC, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_ComposeRotators_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Conv_RotatorToVector_ReturnValue_2) == 0x0000D8, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Conv_RotatorToVector_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Conv_RotatorToVector_ReturnValue_3) == 0x0000E4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Conv_RotatorToVector_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X_2) == 0x0000F0, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y_2) == 0x0000F4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z_2) == 0x0000F8, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X_3) == 0x0000FC, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y_3) == 0x000100, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z_3) == 0x000104, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_3) == 0x000108, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_4) == 0x000110, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue_2) == 0x000118, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue_3) == 0x00011C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X_4) == 0x000120, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y_4) == 0x000124, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z_4) == 0x000128, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Conv_RotatorToVector_ReturnValue_4) == 0x00012C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Conv_RotatorToVector_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_5) == 0x000138, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_X_5) == 0x000140, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_X_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Y_5) == 0x000144, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Y_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_BreakVector_Z_5) == 0x000148, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_BreakVector_Z_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue_4) == 0x00014C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_MakeVector2D_ReturnValue_6) == 0x000150, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_MakeVector2D_ReturnValue_6' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_GetCurrentMOA_ReturnValue) == 0x000158, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_GetCurrentMOA_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_VSize2D_ReturnValue_5) == 0x00015C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_VSize2D_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_3) == 0x000160, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue_1) == 0x000164, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue_2) == 0x000168, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_4) == 0x00016C, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue_3) == 0x000170, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_5) == 0x000174, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_Event_MyGeometry) == 0x000178, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, K2Node_Event_InDeltaTime) == 0x0001B0, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue_4) == 0x0001B4, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_6) == 0x0001B8, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_6' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Add_FloatFloat_ReturnValue_7) == 0x0001BC, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Add_FloatFloat_ReturnValue_7' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator, CallFunc_Multiply_FloatFloat_ReturnValue_5) == 0x0001C0, "Member 'UMG_WeaponHandlingIndicator_C_ExecuteUbergraph_UMG_WeaponHandlingIndicator::CallFunc_Multiply_FloatFloat_ReturnValue_5' has a wrong offset!");

// Function UMG_WeaponHandlingIndicator.UMG_WeaponHandlingIndicator_C.Tick
// 0x003C (0x003C - 0x0000)
struct UMG_WeaponHandlingIndicator_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_WeaponHandlingIndicator_C_Tick) == 0x000004, "Wrong alignment on UMG_WeaponHandlingIndicator_C_Tick");
static_assert(sizeof(UMG_WeaponHandlingIndicator_C_Tick) == 0x00003C, "Wrong size on UMG_WeaponHandlingIndicator_C_Tick");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_Tick, MyGeometry) == 0x000000, "Member 'UMG_WeaponHandlingIndicator_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_WeaponHandlingIndicator_C_Tick, InDeltaTime) == 0x000038, "Member 'UMG_WeaponHandlingIndicator_C_Tick::InDeltaTime' has a wrong offset!");

}

