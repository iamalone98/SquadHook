#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_Inventory

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_Inventory.UMG_Inventory_C
// 0x0060 (0x0310 - 0x02B0)
class UUMG_Inventory_C final : public USQInventoryWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02B0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup;                                // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_0;                            // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_1;                            // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_2;                            // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_3;                            // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_4;                            // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_5;                            // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_6;                            // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_InventoryGroup_C*                  UMG_InventoryGroup_C_7;                            // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_RearmCostInventory_C*              UMG_RearmCostInventory_2;                          // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VerticalBox_0;                                     // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_Inventory(int32 EntryPoint);
	void Construct();
	void PreConstruct(bool IsDesignTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_Inventory_C">();
	}
	static class UUMG_Inventory_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_Inventory_C>();
	}
};
static_assert(alignof(UUMG_Inventory_C) == 0x000008, "Wrong alignment on UUMG_Inventory_C");
static_assert(sizeof(UUMG_Inventory_C) == 0x000310, "Wrong size on UUMG_Inventory_C");
static_assert(offsetof(UUMG_Inventory_C, UberGraphFrame) == 0x0002B0, "Member 'UUMG_Inventory_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup) == 0x0002B8, "Member 'UUMG_Inventory_C::UMG_InventoryGroup' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_0) == 0x0002C0, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_0' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_1) == 0x0002C8, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_1' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_2) == 0x0002D0, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_2' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_3) == 0x0002D8, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_3' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_4) == 0x0002E0, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_4' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_5) == 0x0002E8, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_5' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_6) == 0x0002F0, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_6' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_InventoryGroup_C_7) == 0x0002F8, "Member 'UUMG_Inventory_C::UMG_InventoryGroup_C_7' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, UMG_RearmCostInventory_2) == 0x000300, "Member 'UUMG_Inventory_C::UMG_RearmCostInventory_2' has a wrong offset!");
static_assert(offsetof(UUMG_Inventory_C, VerticalBox_0) == 0x000308, "Member 'UUMG_Inventory_C::VerticalBox_0' has a wrong offset!");

}
