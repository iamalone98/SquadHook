#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ContextMenu

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK::Params
{

// Function W_ContextMenu.W_ContextMenu_C.OnActionExecuted__DelegateSignature
// 0x0004 (0x0004 - 0x0000)
struct W_ContextMenu_C_OnActionExecuted__DelegateSignature final
{
public:
	int32                                         ActionIndex;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ContextMenu_C_OnActionExecuted__DelegateSignature) == 0x000004, "Wrong alignment on W_ContextMenu_C_OnActionExecuted__DelegateSignature");
static_assert(sizeof(W_ContextMenu_C_OnActionExecuted__DelegateSignature) == 0x000004, "Wrong size on W_ContextMenu_C_OnActionExecuted__DelegateSignature");
static_assert(offsetof(W_ContextMenu_C_OnActionExecuted__DelegateSignature, ActionIndex) == 0x000000, "Member 'W_ContextMenu_C_OnActionExecuted__DelegateSignature::ActionIndex' has a wrong offset!");

// Function W_ContextMenu.W_ContextMenu_C.ExecuteUbergraph_W_ContextMenu
// 0x0068 (0x0068 - 0x0000)
struct W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu final
{
public:
	int32                                         EntryPoint;                                        // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void()>                             K2Node_CreateDelegate_OutputDelegate;              // 0x0004(0x0010)(ZeroConstructor, NoDestructor)
	uint8                                         Pad_2FF8[0x4];                                     // 0x0014(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           CallFunc_K2_SetTimerDelegate_ReturnValue;          // 0x0018(0x0008)(NoDestructor, HasGetValueTypeHash)
	struct FGeometry                              K2Node_Event_MyGeometry;                           // 0x0020(0x0038)(IsPlainOldData, NoDestructor)
	float                                         K2Node_Event_InDeltaTime;                          // 0x0058(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         K2Node_CustomEvent_Index;                          // 0x005C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CallFunc_IsHovered_ReturnValue;                    // 0x0060(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_K2_IsTimerActiveHandle_ReturnValue;       // 0x0061(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	bool                                          CallFunc_Not_PreBool_ReturnValue;                  // 0x0062(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu) == 0x000008, "Wrong alignment on W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu");
static_assert(sizeof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu) == 0x000068, "Wrong size on W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, EntryPoint) == 0x000000, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::EntryPoint' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, K2Node_CreateDelegate_OutputDelegate) == 0x000004, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, CallFunc_K2_SetTimerDelegate_ReturnValue) == 0x000018, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::CallFunc_K2_SetTimerDelegate_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, K2Node_Event_MyGeometry) == 0x000020, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::K2Node_Event_MyGeometry' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, K2Node_Event_InDeltaTime) == 0x000058, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::K2Node_Event_InDeltaTime' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, K2Node_CustomEvent_Index) == 0x00005C, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::K2Node_CustomEvent_Index' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, CallFunc_IsHovered_ReturnValue) == 0x000060, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::CallFunc_IsHovered_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, CallFunc_K2_IsTimerActiveHandle_ReturnValue) == 0x000061, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::CallFunc_K2_IsTimerActiveHandle_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu, CallFunc_Not_PreBool_ReturnValue) == 0x000062, "Member 'W_ContextMenu_C_ExecuteUbergraph_W_ContextMenu::CallFunc_Not_PreBool_ReturnValue' has a wrong offset!");

// Function W_ContextMenu.W_ContextMenu_C.OnEntryPressed
// 0x0004 (0x0004 - 0x0000)
struct W_ContextMenu_C_OnEntryPressed final
{
public:
	int32                                         Param_Index;                                       // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ContextMenu_C_OnEntryPressed) == 0x000004, "Wrong alignment on W_ContextMenu_C_OnEntryPressed");
static_assert(sizeof(W_ContextMenu_C_OnEntryPressed) == 0x000004, "Wrong size on W_ContextMenu_C_OnEntryPressed");
static_assert(offsetof(W_ContextMenu_C_OnEntryPressed, Param_Index) == 0x000000, "Member 'W_ContextMenu_C_OnEntryPressed::Param_Index' has a wrong offset!");

// Function W_ContextMenu.W_ContextMenu_C.Tick
// 0x003C (0x003C - 0x0000)
struct W_ContextMenu_C_Tick final
{
public:
	struct FGeometry                              MyGeometry;                                        // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
	float                                         InDeltaTime;                                       // 0x0038(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ContextMenu_C_Tick) == 0x000004, "Wrong alignment on W_ContextMenu_C_Tick");
static_assert(sizeof(W_ContextMenu_C_Tick) == 0x00003C, "Wrong size on W_ContextMenu_C_Tick");
static_assert(offsetof(W_ContextMenu_C_Tick, MyGeometry) == 0x000000, "Member 'W_ContextMenu_C_Tick::MyGeometry' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_Tick, InDeltaTime) == 0x000038, "Member 'W_ContextMenu_C_Tick::InDeltaTime' has a wrong offset!");

// Function W_ContextMenu.W_ContextMenu_C.CreateList
// 0x0068 (0x0068 - 0x0000)
struct W_ContextMenu_C_CreateList final
{
public:
	TArray<class FText>                           Array;                                             // 0x0000(0x0010)(BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
	int32                                         CallFunc_Array_Length_ReturnValue;                 // 0x0010(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Array_Index_Variable;                     // 0x0014(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Temp_int_Loop_Counter_Variable;                    // 0x0018(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FF9[0x4];                                     // 0x001C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CallFunc_Array_Get_Item;                           // 0x0020(0x0018)()
	bool                                          CallFunc_Less_IntInt_ReturnValue;                  // 0x0038(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2FFA[0x3];                                     // 0x0039(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CallFunc_Add_IntInt_ReturnValue;                   // 0x003C(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TDelegate<void(int32 Index)>                  K2Node_CreateDelegate_OutputDelegate;              // 0x0040(0x0010)(ZeroConstructor, NoDestructor)
	class APlayerController*                      CallFunc_GetOwningPlayer_ReturnValue;              // 0x0050(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_ContextEntry_C*                      CallFunc_Create_ReturnValue;                       // 0x0058(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UPanelSlot*                             CallFunc_AddChild_ReturnValue;                     // 0x0060(0x0008)(ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(W_ContextMenu_C_CreateList) == 0x000008, "Wrong alignment on W_ContextMenu_C_CreateList");
static_assert(sizeof(W_ContextMenu_C_CreateList) == 0x000068, "Wrong size on W_ContextMenu_C_CreateList");
static_assert(offsetof(W_ContextMenu_C_CreateList, Array) == 0x000000, "Member 'W_ContextMenu_C_CreateList::Array' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_Array_Length_ReturnValue) == 0x000010, "Member 'W_ContextMenu_C_CreateList::CallFunc_Array_Length_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, Temp_int_Array_Index_Variable) == 0x000014, "Member 'W_ContextMenu_C_CreateList::Temp_int_Array_Index_Variable' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, Temp_int_Loop_Counter_Variable) == 0x000018, "Member 'W_ContextMenu_C_CreateList::Temp_int_Loop_Counter_Variable' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_Array_Get_Item) == 0x000020, "Member 'W_ContextMenu_C_CreateList::CallFunc_Array_Get_Item' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_Less_IntInt_ReturnValue) == 0x000038, "Member 'W_ContextMenu_C_CreateList::CallFunc_Less_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_Add_IntInt_ReturnValue) == 0x00003C, "Member 'W_ContextMenu_C_CreateList::CallFunc_Add_IntInt_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, K2Node_CreateDelegate_OutputDelegate) == 0x000040, "Member 'W_ContextMenu_C_CreateList::K2Node_CreateDelegate_OutputDelegate' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_GetOwningPlayer_ReturnValue) == 0x000050, "Member 'W_ContextMenu_C_CreateList::CallFunc_GetOwningPlayer_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_Create_ReturnValue) == 0x000058, "Member 'W_ContextMenu_C_CreateList::CallFunc_Create_ReturnValue' has a wrong offset!");
static_assert(offsetof(W_ContextMenu_C_CreateList, CallFunc_AddChild_ReturnValue) == 0x000060, "Member 'W_ContextMenu_C_CreateList::CallFunc_AddChild_ReturnValue' has a wrong offset!");

}

