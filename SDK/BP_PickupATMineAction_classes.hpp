#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_PickupATMineAction

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialAction_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_PickupATMineAction.BP_PickupATMineAction_C
// 0x0008 (0x0038 - 0x0030)
class UBP_PickupATMineAction_C final : public UBP_RadialAction_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_PickupATMineAction_C;            // 0x0030(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_PickupATMineAction(int32 EntryPoint);
	void OnClicked(class UBaseRadialMenu_C* Raidal_Menu);
	void Pickup_Item(class APlayerController* Player);
	void Player_Left_Radius(class APlayerController* Player);
	void Player_Enter_Radius(class APlayerController* Player, bool Can_Pickup);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_PickupATMineAction_C">();
	}
	static class UBP_PickupATMineAction_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_PickupATMineAction_C>();
	}
};
static_assert(alignof(UBP_PickupATMineAction_C) == 0x000008, "Wrong alignment on UBP_PickupATMineAction_C");
static_assert(sizeof(UBP_PickupATMineAction_C) == 0x000038, "Wrong size on UBP_PickupATMineAction_C");
static_assert(offsetof(UBP_PickupATMineAction_C, UberGraphFrame_BP_PickupATMineAction_C) == 0x000030, "Member 'UBP_PickupATMineAction_C::UberGraphFrame_BP_PickupATMineAction_C' has a wrong offset!");

}

