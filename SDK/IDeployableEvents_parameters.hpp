#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: IDeployableEvents

#include "Basic.hpp"


namespace SDK::Params
{

// Function IDeployableEvents.IDeployableEvents_C.OnServerValidatedItemPlacement
// 0x0008 (0x0008 - 0x0000)
struct IDeployableEvents_C_OnServerValidatedItemPlacement final
{
public:
	class ASQDeployableItem*                      Deployable;                                        // 0x0000(0x0008)(BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(IDeployableEvents_C_OnServerValidatedItemPlacement) == 0x000008, "Wrong alignment on IDeployableEvents_C_OnServerValidatedItemPlacement");
static_assert(sizeof(IDeployableEvents_C_OnServerValidatedItemPlacement) == 0x000008, "Wrong size on IDeployableEvents_C_OnServerValidatedItemPlacement");
static_assert(offsetof(IDeployableEvents_C_OnServerValidatedItemPlacement, Deployable) == 0x000000, "Member 'IDeployableEvents_C_OnServerValidatedItemPlacement::Deployable' has a wrong offset!");

}
