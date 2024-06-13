#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Helicopter_MiniMap

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_Helicopter_MiniMap.W_Helicopter_MiniMap_C.ExecuteUbergraph_W_Helicopter_MiniMap
// 0x01B8 (0x01B8 - 0x0000)
struct W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsEngineActive_ReturnValue;               // 0x0004(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC1[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0008(0x0010)(ZeroConstructor, NoDestructor)
	bool                                          Temp_bool_Has_Been_Initd_Variable;                 // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC2[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQHelicopter2*                         K2Node_CustomEvent_OwningVehicle;                  // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class AWorldSettings*                         CallFunc_GetWorldSettings_ReturnValue;             // 0x0028(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0030(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC3[0x7];                                     // 0x0031(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQWorldSettings*                       K2Node_DynamicCast_AsSQWorld_Settings;             // 0x0038(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0040(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC4[0x7];                                     // 0x0041(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               CallFunc_CreateDynamicMaterialInstance_ReturnValue; // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0050(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetWorldDeltaSeconds_ReturnValue;         // 0x008C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate_1;            // 0x0090(0x0010)(ZeroConstructor, NoDestructor)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x00A0(0x0008)(NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetEndTime_ReturnValue;                   // 0x00A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4DC5[0x4];                                     // 0x00AC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue;                // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue_1;        // 0x00B8(0x0008)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x00C0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          Temp_bool_IsClosed_Variable;                       // 0x00C1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC6[0x6];                                     // 0x00C2(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMGSequencePlayer*                     CallFunc_PlayAnimation_ReturnValue_1;              // 0x00C8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x00D0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x00D1(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x00D2(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_5;                    // 0x00D3(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	struct FVector2D                              CallFunc_GetMapBoundsScale_ReturnValue;            // 0x00D4(0x0008)(ConstParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FBox2D                                 CallFunc_GetWorldBounds_ReturnValue;               // 0x00DC(0x0014)(ConstParm, ZeroConstructor, NoDestructor)
	bool                                          CallFunc_IsAnimationPlayingForward_ReturnValue;    // 0x00F0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC7[0x7];                                     // 0x00F1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetPlayerController_ReturnValue;          // 0x00F8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_NotEqual_BoolBool_ReturnValue;            // 0x0100(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC8[0x7];                                     // 0x0101(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AHUD*                                   CallFunc_GetHUD_ReturnValue;                       // 0x0108(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TScriptInterface<class IBPI_HUD_C>            K2Node_DynamicCast_AsBPI_HUD;                      // 0x0110(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0120(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC9[0x7];                                     // 0x0121(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SQMapCore_C*                         CallFunc_Get_Map_Core_Map_Core;                    // 0x0128(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_6;                    // 0x0130(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DCA[0x3];                                     // 0x0131(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector                                CallFunc_GetVelocity_ReturnValue;                  // 0x0134(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_VSize_ReturnValue;                        // 0x0140(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FRotator                               CallFunc_K2_GetActorRotation_ReturnValue;          // 0x0144(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_Divide_FloatFloat_ReturnValue;            // 0x0150(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0154(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x0158(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x015C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_FClamp_ReturnValue;                       // 0x0160(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0164(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x0168(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Multiply_FloatFloat_ReturnValue;          // 0x016C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x0170(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Vector2DInterpTo_ReturnValue;             // 0x0178(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_K2_GetActorLocation_ReturnValue;          // 0x0180(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector                                CallFunc_RebaseLocalOriginOntoZero_ReturnValue;    // 0x018C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_WorldToMapLocation_OutMapLocation;        // 0x0198(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_WorldToMapLocation_ReturnValue;           // 0x01A0(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DCB[0x3];                                     // 0x01A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         CallFunc_BreakVector2D_X;                          // 0x01A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x01A8(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_1;        // 0x01AC(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue_2;        // 0x01B0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap) == 0x000008, "Wrong alignment on W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap");
static_assert(sizeof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap) == 0x0001B8, "Wrong size on W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, EntryPoint) == 0x000000, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsEngineActive_ReturnValue) == 0x000004, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsEngineActive_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_CreateDelegate_OutputDelegate) == 0x000008, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, Temp_bool_Has_Been_Initd_Variable) == 0x000018, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::Temp_bool_Has_Been_Initd_Variable' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_CustomEvent_OwningVehicle) == 0x000020, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_CustomEvent_OwningVehicle' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetWorldSettings_ReturnValue) == 0x000028, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetWorldSettings_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue) == 0x000030, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_DynamicCast_AsSQWorld_Settings) == 0x000038, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_DynamicCast_AsSQWorld_Settings' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_DynamicCast_bSuccess) == 0x000040, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_CreateDynamicMaterialInstance_ReturnValue) == 0x000048, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_CreateDynamicMaterialInstance_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_Event_MyGeometry) == 0x000050, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_Event_InDeltaTime) == 0x000088, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetWorldDeltaSeconds_ReturnValue) == 0x00008C, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetWorldDeltaSeconds_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_CreateDelegate_OutputDelegate_1) == 0x000090, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_CreateDelegate_OutputDelegate_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x0000A0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetEndTime_ReturnValue) == 0x0000A8, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetEndTime_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_PlayAnimation_ReturnValue) == 0x0000B0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_PlayAnimation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_K2_SetTimerDelegate_ReturnValue_1) == 0x0000B8, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_K2_SetTimerDelegate_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_1) == 0x0000C0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, Temp_bool_IsClosed_Variable) == 0x0000C1, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::Temp_bool_IsClosed_Variable' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_PlayAnimation_ReturnValue_1) == 0x0000C8, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_PlayAnimation_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_2) == 0x0000D0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_3) == 0x0000D1, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_4) == 0x0000D2, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_5) == 0x0000D3, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_5' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetMapBoundsScale_ReturnValue) == 0x0000D4, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetMapBoundsScale_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetWorldBounds_ReturnValue) == 0x0000DC, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetWorldBounds_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsAnimationPlayingForward_ReturnValue) == 0x0000F0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsAnimationPlayingForward_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetPlayerController_ReturnValue) == 0x0000F8, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetPlayerController_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_NotEqual_BoolBool_ReturnValue) == 0x000100, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_NotEqual_BoolBool_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetHUD_ReturnValue) == 0x000108, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetHUD_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_DynamicCast_AsBPI_HUD) == 0x000110, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_DynamicCast_AsBPI_HUD' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, K2Node_DynamicCast_bSuccess_1) == 0x000120, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Get_Map_Core_Map_Core) == 0x000128, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Get_Map_Core_Map_Core' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_IsValid_ReturnValue_6) == 0x000130, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_IsValid_ReturnValue_6' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_GetVelocity_ReturnValue) == 0x000134, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_GetVelocity_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_VSize_ReturnValue) == 0x000140, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_VSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_K2_GetActorRotation_ReturnValue) == 0x000144, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_K2_GetActorRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Divide_FloatFloat_ReturnValue) == 0x000150, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Divide_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_BreakRotator_Roll) == 0x000154, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_BreakRotator_Pitch) == 0x000158, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_BreakRotator_Yaw) == 0x00015C, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_FClamp_ReturnValue) == 0x000160, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_FClamp_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Add_FloatFloat_ReturnValue) == 0x000164, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x000168, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Multiply_FloatFloat_ReturnValue) == 0x00016C, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Multiply_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_MakeVector2D_ReturnValue) == 0x000170, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Vector2DInterpTo_ReturnValue) == 0x000178, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Vector2DInterpTo_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_K2_GetActorLocation_ReturnValue) == 0x000180, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_K2_GetActorLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_RebaseLocalOriginOntoZero_ReturnValue) == 0x00018C, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_RebaseLocalOriginOntoZero_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_WorldToMapLocation_OutMapLocation) == 0x000198, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_WorldToMapLocation_OutMapLocation' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_WorldToMapLocation_ReturnValue) == 0x0001A0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_WorldToMapLocation_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_BreakVector2D_X) == 0x0001A4, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_BreakVector2D_Y) == 0x0001A8, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Subtract_FloatFloat_ReturnValue_1) == 0x0001AC, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Subtract_FloatFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap, CallFunc_Subtract_FloatFloat_ReturnValue_2) == 0x0001B0, "Member 'W_Helicopter_MiniMap_C_ExecuteUbergraph_W_Helicopter_MiniMap::CallFunc_Subtract_FloatFloat_ReturnValue_2' has a wrong offset!");

// Function W_Helicopter_MiniMap.W_Helicopter_MiniMap_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_Helicopter_MiniMap_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Helicopter_MiniMap_C_Tick) == 0x000004, "Wrong alignment on W_Helicopter_MiniMap_C_Tick");
static_assert(sizeof(W_Helicopter_MiniMap_C_Tick) == 0x00003C, "Wrong size on W_Helicopter_MiniMap_C_Tick");
static_assert(offsetof(W_Helicopter_MiniMap_C_Tick, MyGeometry) == 0x000000, "Member 'W_Helicopter_MiniMap_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_Helicopter_MiniMap_C_Tick, InDeltaTime) == 0x000038, "Member 'W_Helicopter_MiniMap_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_Helicopter_MiniMap.W_Helicopter_MiniMap_C.InitializeMap
// 0x0008 (0x0008 - 0x0000)
struct W_Helicopter_MiniMap_C_InitializeMap final
{
public:
	class ASQHelicopter2*                         OwningVehicle;                                     // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_Helicopter_MiniMap_C_InitializeMap) == 0x000008, "Wrong alignment on W_Helicopter_MiniMap_C_InitializeMap");
static_assert(sizeof(W_Helicopter_MiniMap_C_InitializeMap) == 0x000008, "Wrong size on W_Helicopter_MiniMap_C_InitializeMap");
static_assert(offsetof(W_Helicopter_MiniMap_C_InitializeMap, OwningVehicle) == 0x000000, "Member 'W_Helicopter_MiniMap_C_InitializeMap::OwningVehicle' has a wrong offset!");

}
