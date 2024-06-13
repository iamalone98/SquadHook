#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_PickupAmmoBagAction

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialAction_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_PickupAmmoBagAction.BP_PickupAmmoBagAction_C
// 0x0008 (0x0038 - 0x0030)
class UBP_PickupAmmoBagAction_C final : public UBP_RadialAction_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_PickupAmmoBagAction_C;           // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_PickupAmmoBagAction(int32 EntryPoint);
	void OnClicked(class UBaseRadialMenu_C* Raidal_Menu);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_PickupAmmoBagAction_C">();
	}
	static class UBP_PickupAmmoBagAction_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_PickupAmmoBagAction_C>();
	}
};
static_assert(alignof(UBP_PickupAmmoBagAction_C) == 0x000008, "Wrong alignment on UBP_PickupAmmoBagAction_C");
static_assert(sizeof(UBP_PickupAmmoBagAction_C) == 0x000038, "Wrong size on UBP_PickupAmmoBagAction_C");
static_assert(offsetof(UBP_PickupAmmoBagAction_C, UberGraphFrame_BP_PickupAmmoBagAction_C) == 0x000030, "Member 'UBP_PickupAmmoBagAction_C::UberGraphFrame_BP_PickupAmmoBagAction_C' has a wrong offset!");

}

