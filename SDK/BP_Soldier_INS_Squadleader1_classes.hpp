#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Soldier_INS_Squadleader1

#include "Basic.hpp"

#include "BP_Soldier_INS_Rifleman1_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Soldier_INS_Squadleader1.BP_Soldier_INS_Squadleader1_C
// 0x0000 (0x2710 - 0x2710)
class ABP_Soldier_INS_Squadleader1_C : public ABP_Soldier_INS_Rifleman1_C
{
public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Soldier_INS_Squadleader1_C">();
	}
	static class ABP_Soldier_INS_Squadleader1_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Soldier_INS_Squadleader1_C>();
	}
};
static_assert(alignof(ABP_Soldier_INS_Squadleader1_C) == 0x000010, "Wrong alignment on ABP_Soldier_INS_Squadleader1_C");
static_assert(sizeof(ABP_Soldier_INS_Squadleader1_C) == 0x002710, "Wrong size on ABP_Soldier_INS_Squadleader1_C");

}

