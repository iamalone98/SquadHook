#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GotoMenuAction

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialAction_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GotoMenuAction.BP_GotoMenuAction_C
// 0x0010 (0x0040 - 0x0030)
class UBP_GotoMenuAction_C final : public UBP_RadialAction_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_GotoMenuAction_C;                // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UClass*                                 GotoMenuModel;                                     // 0x0038(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GotoMenuAction(int32 EntryPoint);
	void DoAction(class UBaseRadialMenu_C* RadialMenu, class UClass* MenuModel);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GotoMenuAction_C">();
	}
	static class UBP_GotoMenuAction_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_GotoMenuAction_C>();
	}
};
static_assert(alignof(UBP_GotoMenuAction_C) == 0x000008, "Wrong alignment on UBP_GotoMenuAction_C");
static_assert(sizeof(UBP_GotoMenuAction_C) == 0x000040, "Wrong size on UBP_GotoMenuAction_C");
static_assert(offsetof(UBP_GotoMenuAction_C, UberGraphFrame_BP_GotoMenuAction_C) == 0x000030, "Member 'UBP_GotoMenuAction_C::UberGraphFrame_BP_GotoMenuAction_C' has a wrong offset!");
static_assert(offsetof(UBP_GotoMenuAction_C, GotoMenuModel) == 0x000038, "Member 'UBP_GotoMenuAction_C::GotoMenuModel' has a wrong offset!");

}

