#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ContextEntry

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ContextEntry.W_ContextEntry_C
// 0x0048 (0x02A8 - 0x0260)
class UW_ContextEntry_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                MainButton;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_18;                                      // 0x0270(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   Name_W_ContextEntry_C;                             // 0x0278(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	FMulticastInlineDelegateProperty_             OnActionPressed;                                   // 0x0290(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	int32                                         Index_W_ContextEntry_C;                            // 0x02A0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void OnActionPressed__DelegateSignature(int32 Param_Index);
	void ExecuteUbergraph_W_ContextEntry(int32 EntryPoint);
	void BndEvt__Button_16_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ContextEntry_C">();
	}
	static class UW_ContextEntry_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ContextEntry_C>();
	}
};
static_assert(alignof(UW_ContextEntry_C) == 0x000008, "Wrong alignment on UW_ContextEntry_C");
static_assert(sizeof(UW_ContextEntry_C) == 0x0002A8, "Wrong size on UW_ContextEntry_C");
static_assert(offsetof(UW_ContextEntry_C, UberGraphFrame) == 0x000260, "Member 'UW_ContextEntry_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ContextEntry_C, MainButton) == 0x000268, "Member 'UW_ContextEntry_C::MainButton' has a wrong offset!");
static_assert(offsetof(UW_ContextEntry_C, TextBlock_18) == 0x000270, "Member 'UW_ContextEntry_C::TextBlock_18' has a wrong offset!");
static_assert(offsetof(UW_ContextEntry_C, Name_W_ContextEntry_C) == 0x000278, "Member 'UW_ContextEntry_C::Name_W_ContextEntry_C' has a wrong offset!");
static_assert(offsetof(UW_ContextEntry_C, OnActionPressed) == 0x000290, "Member 'UW_ContextEntry_C::OnActionPressed' has a wrong offset!");
static_assert(offsetof(UW_ContextEntry_C, Index_W_ContextEntry_C) == 0x0002A0, "Member 'UW_ContextEntry_C::Index_W_ContextEntry_C' has a wrong offset!");

}
