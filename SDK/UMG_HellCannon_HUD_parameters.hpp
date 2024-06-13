#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_HellCannon_HUD

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Engine_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function UMG_HellCannon_HUD.UMG_HellCannon_HUD_C.ExecuteUbergraph_UMG_HellCannon_HUD
// 0x0068 (0x0068 - 0x0000)
struct UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APawn*                                  CallFunc_GetOwningPlayerPawn_ReturnValue;          // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicleSeat*                         K2Node_DynamicCast_AsSQVehicle_Seat;               // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC1[0x7];                                     // 0x0051(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_Emplaced_HellCannon_Base_C*         K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base; // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD) == 0x000008, "Wrong alignment on UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD");
static_assert(sizeof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD) == 0x000068, "Wrong size on UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, EntryPoint) == 0x000000, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::EntryPoint' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_Event_MyGeometry) == 0x000004, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, CallFunc_GetOwningPlayerPawn_ReturnValue) == 0x000040, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::CallFunc_GetOwningPlayerPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_DynamicCast_AsSQVehicle_Seat) == 0x000048, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_DynamicCast_AsSQVehicle_Seat' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_DynamicCast_bSuccess) == 0x000050, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base) == 0x000058, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, K2Node_DynamicCast_bSuccess_1) == 0x000060, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD, CallFunc_IsValid_ReturnValue) == 0x000061, "Member 'UMG_HellCannon_HUD_C_ExecuteUbergraph_UMG_HellCannon_HUD::CallFunc_IsValid_ReturnValue' has a wrong offset!");

// Function UMG_HellCannon_HUD.UMG_HellCannon_HUD_C.Tick
// 0x003C (0x003C - 0x0000)
struct UMG_HellCannon_HUD_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(UMG_HellCannon_HUD_C_Tick) == 0x000004, "Wrong alignment on UMG_HellCannon_HUD_C_Tick");
static_assert(sizeof(UMG_HellCannon_HUD_C_Tick) == 0x00003C, "Wrong size on UMG_HellCannon_HUD_C_Tick");
static_assert(offsetof(UMG_HellCannon_HUD_C_Tick, MyGeometry) == 0x000000, "Member 'UMG_HellCannon_HUD_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_Tick, InDeltaTime) == 0x000038, "Member 'UMG_HellCannon_HUD_C_Tick::InDeltaTime' has a wrong offset!");

// Function UMG_HellCannon_HUD.UMG_HellCannon_HUD_C.AngleRotationDisplay
// 0x00F0 (0x00F0 - 0x0000)
struct UMG_HellCannon_HUD_C_AngleRotationDisplay final
{
public:
	class APawn*                                  CallFunc_GetOwningPlayerPawn_ReturnValue;          // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0008(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC2[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ABP_Emplaced_HellCannon_Base_C*         K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base; // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC3[0x7];                                     // 0x0019(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQVehicleSeat*                         K2Node_DynamicCast_AsSQVehicle_Seat;               // 0x0020(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4FC4[0x3];                                     // 0x0029(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	struct FRotator                               CallFunc_K2_GetComponentRotation_ReturnValue;      // 0x002C(0x000C)(ZeroConstructor, IsPlainOldData, NoDestructor)
	float                                         CallFunc_BreakRotator_Roll;                        // 0x0038(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Pitch;                       // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakRotator_Yaw;                         // 0x0040(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Add_FloatFloat_ReturnValue;               // 0x0044(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_FloatToText_ReturnValue;             // 0x0048(0x0018)()
	class FString                                 CallFunc_Conv_TextToString_ReturnValue;            // 0x0060(0x0010)(ZeroConstructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0070(0x0018)()
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0088(0x0040)(HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x00C8(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00D8(0x0018)()
};
static_assert(alignof(UMG_HellCannon_HUD_C_AngleRotationDisplay) == 0x000008, "Wrong alignment on UMG_HellCannon_HUD_C_AngleRotationDisplay");
static_assert(sizeof(UMG_HellCannon_HUD_C_AngleRotationDisplay) == 0x0000F0, "Wrong size on UMG_HellCannon_HUD_C_AngleRotationDisplay");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_GetOwningPlayerPawn_ReturnValue) == 0x000000, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_GetOwningPlayerPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_IsValid_ReturnValue) == 0x000008, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base) == 0x000010, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_DynamicCast_AsBP_Emplaced_Hell_Cannon_Base' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_DynamicCast_bSuccess) == 0x000018, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_DynamicCast_AsSQVehicle_Seat) == 0x000020, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_DynamicCast_AsSQVehicle_Seat' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_DynamicCast_bSuccess_1) == 0x000028, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_K2_GetComponentRotation_ReturnValue) == 0x00002C, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_K2_GetComponentRotation_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_BreakRotator_Roll) == 0x000038, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_BreakRotator_Roll' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_BreakRotator_Pitch) == 0x00003C, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_BreakRotator_Pitch' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_BreakRotator_Yaw) == 0x000040, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_BreakRotator_Yaw' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_Add_FloatFloat_ReturnValue) == 0x000044, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_Add_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_Conv_FloatToText_ReturnValue) == 0x000048, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_Conv_FloatToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_Conv_TextToString_ReturnValue) == 0x000060, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_Conv_TextToString_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_Conv_StringToText_ReturnValue) == 0x000070, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_MakeStruct_FormatArgumentData) == 0x000088, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, K2Node_MakeArray_Array) == 0x0000C8, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(UMG_HellCannon_HUD_C_AngleRotationDisplay, CallFunc_Format_ReturnValue) == 0x0000D8, "Member 'UMG_HellCannon_HUD_C_AngleRotationDisplay::CallFunc_Format_ReturnValue' has a wrong offset!");

}

