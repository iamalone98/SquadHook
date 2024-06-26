#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_FactionItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_FactionItem.W_FactionItem_C
// 0x0020 (0x02D0 - 0x02B0)
class UW_FactionItem_C final : public USQFactionItemWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02B0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Hover;                                             // 0x02B8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Border_0;                                          // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	bool                                          bIsHovered;                                        // 0x02C8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_W_FactionItem(int32 EntryPoint);
	void Destruct();
	void ForceUnHovered();
	void ForceOnHovered();
	void BndEvt__ItemButton_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__W_FactionItem_ItemButton_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_0_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_FactionItem_C">();
	}
	static class UW_FactionItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_FactionItem_C>();
	}
};
static_assert(alignof(UW_FactionItem_C) == 0x000008, "Wrong alignment on UW_FactionItem_C");
static_assert(sizeof(UW_FactionItem_C) == 0x0002D0, "Wrong size on UW_FactionItem_C");
static_assert(offsetof(UW_FactionItem_C, UberGraphFrame) == 0x0002B0, "Member 'UW_FactionItem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_FactionItem_C, Hover) == 0x0002B8, "Member 'UW_FactionItem_C::Hover' has a wrong offset!");
static_assert(offsetof(UW_FactionItem_C, Border_0) == 0x0002C0, "Member 'UW_FactionItem_C::Border_0' has a wrong offset!");
static_assert(offsetof(UW_FactionItem_C, bIsHovered) == 0x0002C8, "Member 'UW_FactionItem_C::bIsHovered' has a wrong offset!");

}

