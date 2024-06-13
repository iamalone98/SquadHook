#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_ChangeRoleAction

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialAction_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_ChangeRoleAction.BP_ChangeRoleAction_C
// 0x0008 (0x0038 - 0x0030)
class UBP_ChangeRoleAction_C final : public UBP_RadialAction_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_ChangeRoleAction_C;              // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_ChangeRoleAction(int32 EntryPoint);
	void ChangeRole(class UBaseRadialMenu_C* Radial, class USQRoleSettings* Role);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_ChangeRoleAction_C">();
	}
	static class UBP_ChangeRoleAction_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_ChangeRoleAction_C>();
	}
};
static_assert(alignof(UBP_ChangeRoleAction_C) == 0x000008, "Wrong alignment on UBP_ChangeRoleAction_C");
static_assert(sizeof(UBP_ChangeRoleAction_C) == 0x000038, "Wrong size on UBP_ChangeRoleAction_C");
static_assert(offsetof(UBP_ChangeRoleAction_C, UberGraphFrame_BP_ChangeRoleAction_C) == 0x000030, "Member 'UBP_ChangeRoleAction_C::UberGraphFrame_BP_ChangeRoleAction_C' has a wrong offset!");

}
