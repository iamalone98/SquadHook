#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_AdminBanPopup

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_AdminBanPopup.W_AdminBanPopup_C
// 0x0078 (0x02D8 - 0x0260)
class UW_AdminBanPopup_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                BanButton;                                         // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                CancelButton;                                      // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UEditableTextBox*                       DurationEditBox;                                   // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_132;                                         // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMultiLineEditableTextBox*              ReasonEditTextBox;                                 // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_PlayerName;                                     // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             OnExecuteBan;                                      // 0x0298(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class FText                                   PlayerName;                                        // 0x02A8(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	int32                                         CharacterLimit;                                    // 0x02C0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2FE4[0x4];                                     // 0x02C4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           TimerHandle;                                       // 0x02C8(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	float                                         ClearTime;                                         // 0x02D0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void OnExecuteBan__DelegateSignature(const class FText& Reason, const class FText& Time);
	void ExecuteUbergraph_W_AdminBanPopup(int32 EntryPoint);
	void OnHoveredEnd();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void BndEvt__Button_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature();
	void BndEvt__Button_118_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	class FText Get_PlayerName();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_AdminBanPopup_C">();
	}
	static class UW_AdminBanPopup_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_AdminBanPopup_C>();
	}
};
static_assert(alignof(UW_AdminBanPopup_C) == 0x000008, "Wrong alignment on UW_AdminBanPopup_C");
static_assert(sizeof(UW_AdminBanPopup_C) == 0x0002D8, "Wrong size on UW_AdminBanPopup_C");
static_assert(offsetof(UW_AdminBanPopup_C, UberGraphFrame) == 0x000260, "Member 'UW_AdminBanPopup_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, BanButton) == 0x000268, "Member 'UW_AdminBanPopup_C::BanButton' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, CancelButton) == 0x000270, "Member 'UW_AdminBanPopup_C::CancelButton' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, DurationEditBox) == 0x000278, "Member 'UW_AdminBanPopup_C::DurationEditBox' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, Image_132) == 0x000280, "Member 'UW_AdminBanPopup_C::Image_132' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, ReasonEditTextBox) == 0x000288, "Member 'UW_AdminBanPopup_C::ReasonEditTextBox' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, TB_PlayerName) == 0x000290, "Member 'UW_AdminBanPopup_C::TB_PlayerName' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, OnExecuteBan) == 0x000298, "Member 'UW_AdminBanPopup_C::OnExecuteBan' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, PlayerName) == 0x0002A8, "Member 'UW_AdminBanPopup_C::PlayerName' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, CharacterLimit) == 0x0002C0, "Member 'UW_AdminBanPopup_C::CharacterLimit' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, TimerHandle) == 0x0002C8, "Member 'UW_AdminBanPopup_C::TimerHandle' has a wrong offset!");
static_assert(offsetof(UW_AdminBanPopup_C, ClearTime) == 0x0002D0, "Member 'UW_AdminBanPopup_C::ClearTime' has a wrong offset!");

}

