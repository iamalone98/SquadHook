#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQRoamingMap

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"
#include "SlateCore_structs.hpp"


namespace SDK::Params
{

// Function W_SQRoamingMap.W_SQRoamingMap_C.ExecuteUbergraph_W_SQRoamingMap
// 0x00B0 (0x00B0 - 0x0000)
struct W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_GetOwningPawnMapScreenPosition_Result;    // 0x0004(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetOwningPawnMapScreenPosition_Success;   // 0x000C(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsAnimationPlayingForward_ReturnValue;    // 0x000D(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA0[0x2];                                     // 0x000E(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0010(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0048(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2DA1[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller;          // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA2[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    K2Node_DynamicCast_AsSQPlayer_Controller_1;        // 0x0068(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess_1;                     // 0x0070(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          K2Node_Event_IsDesignTime;                         // 0x0071(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA3[0x2];                                     // 0x0072(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector2D                              CallFunc_GetViewportSize_ReturnValue;              // 0x0074(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2DA4[0x4];                                     // 0x007C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UCanvasPanelSlot*                       CallFunc_SlotAsCanvasSlot_ReturnValue;             // 0x0080(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetViewportScale_ReturnValue;             // 0x0088(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Divide_Vector2DFloat_ReturnValue;         // 0x008C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_Divide_Vector2DFloat_ReturnValue_1;       // 0x0094(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_X;                          // 0x009C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_BreakVector2D_Y;                          // 0x00A0(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_Subtract_FloatFloat_ReturnValue;          // 0x00A4(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x00A8(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap) == 0x000008, "Wrong alignment on W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap");
static_assert(sizeof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap) == 0x0000B0, "Wrong size on W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, EntryPoint) == 0x000000, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_GetOwningPawnMapScreenPosition_Result) == 0x000004, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_GetOwningPawnMapScreenPosition_Result' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_GetOwningPawnMapScreenPosition_Success) == 0x00000C, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_GetOwningPawnMapScreenPosition_Success' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_IsAnimationPlayingForward_ReturnValue) == 0x00000D, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_IsAnimationPlayingForward_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_Event_MyGeometry) == 0x000010, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_Event_InDeltaTime) == 0x000048, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_GetOwningPlayer_ReturnValue) == 0x000050, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_DynamicCast_AsSQPlayer_Controller) == 0x000058, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_DynamicCast_AsSQPlayer_Controller' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_DynamicCast_bSuccess) == 0x000060, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_DynamicCast_AsSQPlayer_Controller_1) == 0x000068, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_DynamicCast_AsSQPlayer_Controller_1' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_DynamicCast_bSuccess_1) == 0x000070, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_DynamicCast_bSuccess_1' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, K2Node_Event_IsDesignTime) == 0x000071, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::K2Node_Event_IsDesignTime' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_GetViewportSize_ReturnValue) == 0x000074, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_GetViewportSize_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_SlotAsCanvasSlot_ReturnValue) == 0x000080, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_SlotAsCanvasSlot_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_GetViewportScale_ReturnValue) == 0x000088, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_GetViewportScale_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_Divide_Vector2DFloat_ReturnValue) == 0x00008C, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_Divide_Vector2DFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_Divide_Vector2DFloat_ReturnValue_1) == 0x000094, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_Divide_Vector2DFloat_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_BreakVector2D_X) == 0x00009C, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_BreakVector2D_X' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_BreakVector2D_Y) == 0x0000A0, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_BreakVector2D_Y' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_Subtract_FloatFloat_ReturnValue) == 0x0000A4, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_Subtract_FloatFloat_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap, CallFunc_MakeVector2D_ReturnValue) == 0x0000A8, "Member 'W_SQRoamingMap_C_ExecuteUbergraph_W_SQRoamingMap::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");

// Function W_SQRoamingMap.W_SQRoamingMap_C.PreConstruct
// 0x0001 (0x0001 - 0x0000)
struct W_SQRoamingMap_C_PreConstruct final
{
public:
	bool                                          IsDesignTime;                                      // 0x0000(0x0001)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_SQRoamingMap_C_PreConstruct) == 0x000001, "Wrong alignment on W_SQRoamingMap_C_PreConstruct");
static_assert(sizeof(W_SQRoamingMap_C_PreConstruct) == 0x000001, "Wrong size on W_SQRoamingMap_C_PreConstruct");
static_assert(offsetof(W_SQRoamingMap_C_PreConstruct, IsDesignTime) == 0x000000, "Member 'W_SQRoamingMap_C_PreConstruct::IsDesignTime' has a wrong offset!");

// Function W_SQRoamingMap.W_SQRoamingMap_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_SQRoamingMap_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SQRoamingMap_C_Tick) == 0x000004, "Wrong alignment on W_SQRoamingMap_C_Tick");
static_assert(sizeof(W_SQRoamingMap_C_Tick) == 0x00003C, "Wrong size on W_SQRoamingMap_C_Tick");
static_assert(offsetof(W_SQRoamingMap_C_Tick, MyGeometry) == 0x000000, "Member 'W_SQRoamingMap_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_Tick, InDeltaTime) == 0x000038, "Member 'W_SQRoamingMap_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_SQRoamingMap.W_SQRoamingMap_C.GetOwningPawnMapScreenPosition
// 0x0068 (0x0068 - 0x0000)
struct W_SQRoamingMap_C_GetOwningPawnMapScreenPosition final
{
public:
	struct FVector2D                              Result;                                            // 0x0000(0x0008)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Success;                                           // 0x0008(0x0001)(Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA5[0x7];                                     // 0x0009(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  PlayerPawn;                                        // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQCoreStateComponent*                  CallFunc_GetComponentByClass_ReturnValue;          // 0x0020(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue;                      // 0x0028(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA6[0x7];                                     // 0x0029(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         K2Node_DynamicCast_AsSQPlayer_State;               // 0x0030(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          K2Node_DynamicCast_bSuccess;                       // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA7[0x7];                                     // 0x0039(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  CallFunc_GetCurrentPawn_ReturnValue;               // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             CallFunc_GetCurrentVehicle_ReturnValue;            // 0x0048(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_1;                    // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA8[0x1];                                     // 0x0051(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQCoreStateId                         CallFunc_GetId_ReturnValue;                        // 0x0052(0x0002)(NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsValid_ReturnValue_2;                    // 0x0054(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_3;                    // 0x0055(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DA9[0x2];                                     // 0x0056(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector2D                              CallFunc_GetWidgetScreenPosition_OutPosition;      // 0x0058(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetWidgetScreenPosition_ReturnValue;      // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_IsValid_ReturnValue_4;                    // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition) == 0x000008, "Wrong alignment on W_SQRoamingMap_C_GetOwningPawnMapScreenPosition");
static_assert(sizeof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition) == 0x000068, "Wrong size on W_SQRoamingMap_C_GetOwningPawnMapScreenPosition");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, Result) == 0x000000, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::Result' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, Success) == 0x000008, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::Success' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, PlayerPawn) == 0x000010, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::PlayerPawn' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetOwningPlayer_ReturnValue) == 0x000018, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetComponentByClass_ReturnValue) == 0x000020, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetComponentByClass_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_IsValid_ReturnValue) == 0x000028, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_IsValid_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, K2Node_DynamicCast_AsSQPlayer_State) == 0x000030, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::K2Node_DynamicCast_AsSQPlayer_State' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, K2Node_DynamicCast_bSuccess) == 0x000038, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::K2Node_DynamicCast_bSuccess' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetCurrentPawn_ReturnValue) == 0x000040, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetCurrentPawn_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetCurrentVehicle_ReturnValue) == 0x000048, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetCurrentVehicle_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_IsValid_ReturnValue_1) == 0x000050, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_IsValid_ReturnValue_1' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetId_ReturnValue) == 0x000052, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetId_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_IsValid_ReturnValue_2) == 0x000054, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_IsValid_ReturnValue_2' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_IsValid_ReturnValue_3) == 0x000055, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_IsValid_ReturnValue_3' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetWidgetScreenPosition_OutPosition) == 0x000058, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetWidgetScreenPosition_OutPosition' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_GetWidgetScreenPosition_ReturnValue) == 0x000060, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_GetWidgetScreenPosition_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_SQRoamingMap_C_GetOwningPawnMapScreenPosition, CallFunc_IsValid_ReturnValue_4) == 0x000061, "Member 'W_SQRoamingMap_C_GetOwningPawnMapScreenPosition::CallFunc_IsValid_ReturnValue_4' has a wrong offset!");

// Function W_SQRoamingMap.W_SQRoamingMap_C.MouseWheelZoom
// 0x0004 (0x0004 - 0x0000)
struct W_SQRoamingMap_C_MouseWheelZoom final
{
public:
	float                                         MouseWheelAxis;                                    // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_SQRoamingMap_C_MouseWheelZoom) == 0x000004, "Wrong alignment on W_SQRoamingMap_C_MouseWheelZoom");
static_assert(sizeof(W_SQRoamingMap_C_MouseWheelZoom) == 0x000004, "Wrong size on W_SQRoamingMap_C_MouseWheelZoom");
static_assert(offsetof(W_SQRoamingMap_C_MouseWheelZoom, MouseWheelAxis) == 0x000000, "Member 'W_SQRoamingMap_C_MouseWheelZoom::MouseWheelAxis' has a wrong offset!");

}

