#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_MousePosition

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"


namespace SDK::Params
{

// Function W_MousePosition.W_MousePosition_C.ExecuteUbergraph_W_MousePosition
// 0x00E0 (0x00E0 - 0x0000)
struct W_MousePosition_C_ExecuteUbergraph_W_MousePosition final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0004(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0040(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CallFunc_Conv_StringToText_ReturnValue;            // 0x0048(0x0018)()
	float                                         CallFunc_GetMousePositionScaledByDPI_LocationX;    // 0x0060(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CallFunc_GetMousePositionScaledByDPI_LocationY;    // 0x0064(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_GetMousePositionScaledByDPI_ReturnValue;  // 0x0068(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2BDB[0x7];                                     // 0x0069(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FFormatArgumentData                    K2Node_MakeStruct_FormatArgumentData;              // 0x0070(0x0040)(HasGetValueTypeHash)
	struct FVector2D                              CallFunc_MakeVector2D_ReturnValue;                 // 0x00B0(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<struct FFormatArgumentData>            K2Node_MakeArray_Array;                            // 0x00B8(0x0010)(ReferenceParm)
	class FText                                   CallFunc_Format_ReturnValue;                       // 0x00C8(0x0018)()
};
static_assert(alignof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition) == 0x000008, "Wrong alignment on W_MousePosition_C_ExecuteUbergraph_W_MousePosition");
static_assert(sizeof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition) == 0x0000E0, "Wrong size on W_MousePosition_C_ExecuteUbergraph_W_MousePosition");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, EntryPoint) == 0x000000, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, K2Node_Event_MyGeometry) == 0x000004, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, K2Node_Event_InDeltaTime) == 0x00003C, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_GetOwningPlayer_ReturnValue) == 0x000040, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_Conv_StringToText_ReturnValue) == 0x000048, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_Conv_StringToText_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_GetMousePositionScaledByDPI_LocationX) == 0x000060, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_GetMousePositionScaledByDPI_LocationX' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_GetMousePositionScaledByDPI_LocationY) == 0x000064, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_GetMousePositionScaledByDPI_LocationY' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_GetMousePositionScaledByDPI_ReturnValue) == 0x000068, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_GetMousePositionScaledByDPI_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, K2Node_MakeStruct_FormatArgumentData) == 0x000070, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::K2Node_MakeStruct_FormatArgumentData' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_MakeVector2D_ReturnValue) == 0x0000B0, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_MakeVector2D_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, K2Node_MakeArray_Array) == 0x0000B8, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::K2Node_MakeArray_Array' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_ExecuteUbergraph_W_MousePosition, CallFunc_Format_ReturnValue) == 0x0000C8, "Member 'W_MousePosition_C_ExecuteUbergraph_W_MousePosition::CallFunc_Format_ReturnValue' has a wrong offset!");

// Function W_MousePosition.W_MousePosition_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_MousePosition_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_MousePosition_C_Tick) == 0x000004, "Wrong alignment on W_MousePosition_C_Tick");
static_assert(sizeof(W_MousePosition_C_Tick) == 0x00003C, "Wrong size on W_MousePosition_C_Tick");
static_assert(offsetof(W_MousePosition_C_Tick, MyGeometry) == 0x000000, "Member 'W_MousePosition_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_MousePosition_C_Tick, InDeltaTime) == 0x000038, "Member 'W_MousePosition_C_Tick::InDeltaTime' has a wrong offset!");

}
