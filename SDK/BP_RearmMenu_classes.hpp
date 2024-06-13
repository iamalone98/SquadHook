#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_RearmMenu

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "BP_RadialMenuModel_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_RearmMenu.BP_RearmMenu_C
// 0x0030 (0x0088 - 0x0058)
class UBP_RearmMenu_C final : public UBP_RadialMenuModel_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_RearmMenu_C;                     // 0x0058(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBP_RearmWeaponDynamicModel_C*          RearmGroupGenericModel;                            // 0x0060(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBPRadialPopulatorRearmGroup_C*         RearmPopulator;                                    // 0x0068(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQRearmType                                  RearmType;                                         // 0x0070(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_40F8[0x7];                                     // 0x0071(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class URadialCenterRearmButton_C*             RearmCenterButton;                                 // 0x0078(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQPawnInventoryComponent*              InventoryComponent;                                // 0x0080(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_RearmMenu(int32 EntryPoint);
	void CreateChildWidgets(class UBaseRadialMenu_C* BaseRadialMenu);
	void CreateWidgets(class UBaseRadialMenu_C* InputPin);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_RearmMenu_C">();
	}
	static class UBP_RearmMenu_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_RearmMenu_C>();
	}
};
static_assert(alignof(UBP_RearmMenu_C) == 0x000008, "Wrong alignment on UBP_RearmMenu_C");
static_assert(sizeof(UBP_RearmMenu_C) == 0x000088, "Wrong size on UBP_RearmMenu_C");
static_assert(offsetof(UBP_RearmMenu_C, UberGraphFrame_BP_RearmMenu_C) == 0x000058, "Member 'UBP_RearmMenu_C::UberGraphFrame_BP_RearmMenu_C' has a wrong offset!");
static_assert(offsetof(UBP_RearmMenu_C, RearmGroupGenericModel) == 0x000060, "Member 'UBP_RearmMenu_C::RearmGroupGenericModel' has a wrong offset!");
static_assert(offsetof(UBP_RearmMenu_C, RearmPopulator) == 0x000068, "Member 'UBP_RearmMenu_C::RearmPopulator' has a wrong offset!");
static_assert(offsetof(UBP_RearmMenu_C, RearmType) == 0x000070, "Member 'UBP_RearmMenu_C::RearmType' has a wrong offset!");
static_assert(offsetof(UBP_RearmMenu_C, RearmCenterButton) == 0x000078, "Member 'UBP_RearmMenu_C::RearmCenterButton' has a wrong offset!");
static_assert(offsetof(UBP_RearmMenu_C, InventoryComponent) == 0x000080, "Member 'UBP_RearmMenu_C::InventoryComponent' has a wrong offset!");

}

