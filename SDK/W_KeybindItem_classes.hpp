#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_KeybindItem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_KeybindItem.W_KeybindItem_C
// 0x0030 (0x0290 - 0x0260)
class UW_KeybindItem_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UTextBlock*                             KeybindText;                                       // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_1;                                         // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   KeyBind;                                           // 0x0278(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)

public:
	void ExecuteUbergraph_W_KeybindItem(int32 EntryPoint);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_KeybindItem_C">();
	}
	static class UW_KeybindItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_KeybindItem_C>();
	}
};
static_assert(alignof(UW_KeybindItem_C) == 0x000008, "Wrong alignment on UW_KeybindItem_C");
static_assert(sizeof(UW_KeybindItem_C) == 0x000290, "Wrong size on UW_KeybindItem_C");
static_assert(offsetof(UW_KeybindItem_C, UberGraphFrame) == 0x000260, "Member 'UW_KeybindItem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_KeybindItem_C, KeybindText) == 0x000268, "Member 'UW_KeybindItem_C::KeybindText' has a wrong offset!");
static_assert(offsetof(UW_KeybindItem_C, SizeBox_1) == 0x000270, "Member 'UW_KeybindItem_C::SizeBox_1' has a wrong offset!");
static_assert(offsetof(UW_KeybindItem_C, KeyBind) == 0x000278, "Member 'UW_KeybindItem_C::KeyBind' has a wrong offset!");

}

