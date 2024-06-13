#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_BTR80_MIL_turret

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_BTR80_RUS_turret_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_BTR80_MIL_turret.BP_BTR80_MIL_turret_C
// 0x0000 (0x04C0 - 0x04C0)
class ABP_BTR80_MIL_turret_C final : public ABP_BTR80_RUS_turret_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_BTR80_MIL_turret_C;              // 0x04B8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_BTR80_MIL_turret(int32 EntryPoint);
	void ReceiveBeginPlay();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_BTR80_MIL_turret_C">();
	}
	static class ABP_BTR80_MIL_turret_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_BTR80_MIL_turret_C>();
	}
};
static_assert(alignof(ABP_BTR80_MIL_turret_C) == 0x000010, "Wrong alignment on ABP_BTR80_MIL_turret_C");
static_assert(sizeof(ABP_BTR80_MIL_turret_C) == 0x0004C0, "Wrong size on ABP_BTR80_MIL_turret_C");
static_assert(offsetof(ABP_BTR80_MIL_turret_C, UberGraphFrame_BP_BTR80_MIL_turret_C) == 0x0004B8, "Member 'ABP_BTR80_MIL_turret_C::UberGraphFrame_BP_BTR80_MIL_turret_C' has a wrong offset!");

}

