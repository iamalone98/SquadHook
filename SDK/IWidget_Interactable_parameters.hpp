#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IWidget_Interactable

#include "Basic.hpp"

#include "Squad_structs.hpp"


namespace SDK::Params
{

// Function IWidget_Interactable.IWidget_Interactable_C.Set Interactable Actor
// 0x0008 (0x0008 - 0x0000)
struct IWidget_Interactable_C_Set_Interactable_Actor final
{
public:
	class AActor*                                 Actor;                                             // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(IWidget_Interactable_C_Set_Interactable_Actor) == 0x000008, "Wrong alignment on IWidget_Interactable_C_Set_Interactable_Actor");
static_assert(sizeof(IWidget_Interactable_C_Set_Interactable_Actor) == 0x000008, "Wrong size on IWidget_Interactable_C_Set_Interactable_Actor");
static_assert(offsetof(IWidget_Interactable_C_Set_Interactable_Actor, Actor) == 0x000000, "Member 'IWidget_Interactable_C_Set_Interactable_Actor::Actor' has a wrong offset!");

// Function IWidget_Interactable.IWidget_Interactable_C.Set Interact Data
// 0x0040 (0x0040 - 0x0000)
struct IWidget_Interactable_C_Set_Interact_Data final
{
public:
	struct FSQUsableWidgetData                    Interact_Data;                                     // 0x0000(0x0038)(BlueprintVisible, BlueprintReadOnly, Parm)
	class AActor*                                 Actor;                                             // 0x0038(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(IWidget_Interactable_C_Set_Interact_Data) == 0x000008, "Wrong alignment on IWidget_Interactable_C_Set_Interact_Data");
static_assert(sizeof(IWidget_Interactable_C_Set_Interact_Data) == 0x000040, "Wrong size on IWidget_Interactable_C_Set_Interact_Data");
static_assert(offsetof(IWidget_Interactable_C_Set_Interact_Data, Interact_Data) == 0x000000, "Member 'IWidget_Interactable_C_Set_Interact_Data::Interact_Data' has a wrong offset!");
static_assert(offsetof(IWidget_Interactable_C_Set_Interact_Data, Actor) == 0x000038, "Member 'IWidget_Interactable_C_Set_Interact_Data::Actor' has a wrong offset!");

}

