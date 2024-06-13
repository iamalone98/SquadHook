#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: ChallengeWindow

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass ChallengeWindow.ChallengeWindow_C
// 0x00C0 (0x0320 - 0x0260)
class UChallengeWindow_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UW_MainMenuButton_C*                    AcceptButton;                                      // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BottomBorder;                                      // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    DenyButton;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Description;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Line;                                              // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TitleTextBlock;                                    // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TopBorder;                                         // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   TitleText;                                         // 0x02A0(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	class FText                                   DescriptionText;                                   // 0x02B8(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	class FText                                   LeftButtonText;                                    // 0x02D0(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	class FText                                   RightButtonText;                                   // 0x02E8(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	FMulticastInlineDelegateProperty_             OnLeftButtonClicked;                               // 0x0300(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnRightButtonClicked;                              // 0x0310(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void OnLeftButtonClicked__DelegateSignature();
	void OnRightButtonClicked__DelegateSignature();
	void ExecuteUbergraph_ChallengeWindow(int32 EntryPoint);
	void BndEvt__DenyButton_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__AcceptButton_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void PreConstruct(bool IsDesignTime);
	void Construct();
	void SetDescription(const class FText& InDescription);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"ChallengeWindow_C">();
	}
	static class UChallengeWindow_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UChallengeWindow_C>();
	}
};
static_assert(alignof(UChallengeWindow_C) == 0x000008, "Wrong alignment on UChallengeWindow_C");
static_assert(sizeof(UChallengeWindow_C) == 0x000320, "Wrong size on UChallengeWindow_C");
static_assert(offsetof(UChallengeWindow_C, UberGraphFrame) == 0x000260, "Member 'UChallengeWindow_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, AcceptButton) == 0x000268, "Member 'UChallengeWindow_C::AcceptButton' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, BottomBorder) == 0x000270, "Member 'UChallengeWindow_C::BottomBorder' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, DenyButton) == 0x000278, "Member 'UChallengeWindow_C::DenyButton' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, Description) == 0x000280, "Member 'UChallengeWindow_C::Description' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, Line) == 0x000288, "Member 'UChallengeWindow_C::Line' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, TitleTextBlock) == 0x000290, "Member 'UChallengeWindow_C::TitleTextBlock' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, TopBorder) == 0x000298, "Member 'UChallengeWindow_C::TopBorder' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, TitleText) == 0x0002A0, "Member 'UChallengeWindow_C::TitleText' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, DescriptionText) == 0x0002B8, "Member 'UChallengeWindow_C::DescriptionText' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, LeftButtonText) == 0x0002D0, "Member 'UChallengeWindow_C::LeftButtonText' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, RightButtonText) == 0x0002E8, "Member 'UChallengeWindow_C::RightButtonText' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, OnLeftButtonClicked) == 0x000300, "Member 'UChallengeWindow_C::OnLeftButtonClicked' has a wrong offset!");
static_assert(offsetof(UChallengeWindow_C, OnRightButtonClicked) == 0x000310, "Member 'UChallengeWindow_C::OnRightButtonClicked' has a wrong offset!");

}

