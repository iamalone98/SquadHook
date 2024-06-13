#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Role_Inventory_Item

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_Role_Inventory_Item.BP_Role_Inventory_Item_C
// 0x0018 (0x0278 - 0x0260)
class UBP_Role_Inventory_Item_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Icon;                                              // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTexture2D*                             Texture;                                           // 0x0270(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Role_Inventory_Item(int32 EntryPoint);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Role_Inventory_Item_C">();
	}
	static class UBP_Role_Inventory_Item_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Role_Inventory_Item_C>();
	}
};
static_assert(alignof(UBP_Role_Inventory_Item_C) == 0x000008, "Wrong alignment on UBP_Role_Inventory_Item_C");
static_assert(sizeof(UBP_Role_Inventory_Item_C) == 0x000278, "Wrong size on UBP_Role_Inventory_Item_C");
static_assert(offsetof(UBP_Role_Inventory_Item_C, UberGraphFrame) == 0x000260, "Member 'UBP_Role_Inventory_Item_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_Role_Inventory_Item_C, Icon) == 0x000268, "Member 'UBP_Role_Inventory_Item_C::Icon' has a wrong offset!");
static_assert(offsetof(UBP_Role_Inventory_Item_C, Texture) == 0x000270, "Member 'UBP_Role_Inventory_Item_C::Texture' has a wrong offset!");

}

