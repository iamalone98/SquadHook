#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: I_UI_Events

#include "Basic.hpp"


namespace SDK::Params
{

// Function I_UI_Events.I_UI_Events_C.Team Selected
// 0x0004 (0x0004 - 0x0000)
struct I_UI_Events_C_Team_Selected final
{
public:
	int32                                         Team_ID;                                           // 0x0000(0x0004)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(I_UI_Events_C_Team_Selected) == 0x000004, "Wrong alignment on I_UI_Events_C_Team_Selected");
static_assert(sizeof(I_UI_Events_C_Team_Selected) == 0x000004, "Wrong size on I_UI_Events_C_Team_Selected");
static_assert(offsetof(I_UI_Events_C_Team_Selected, Team_ID) == 0x000000, "Member 'I_UI_Events_C_Team_Selected::Team_ID' has a wrong offset!");

}
