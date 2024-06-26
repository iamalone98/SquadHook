#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: MainMenu_ExitButtons

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass MainMenu_ExitButtons.MainMenu_ExitButtons_C
// 0x0048 (0x02A8 - 0x0260)
class UMainMenu_ExitButtons_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UMainMenu_Button_C*                     ButtonEXIT;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                HoverCheckArea;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Line;                                              // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     MainMenu_Button_Development;                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	bool                                          Was_hovered;                                       // 0x0288(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_350E[0x7];                                     // 0x0289(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenuScreen_C*                      REF_MainMenu;                                      // 0x0290(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             OnUnhovered;                                       // 0x0298(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void OnUnHovered__DelegateSignature();
	void ExecuteUbergraph_MainMenu_ExitButtons(int32 EntryPoint);
	void BndEvt__ButtonExit_K2Node_ComponentBoundEvent_17_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__MainMenu_Button_Development_K2Node_ComponentBoundEvent_10_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	ESlateVisibility GetVisibility_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"MainMenu_ExitButtons_C">();
	}
	static class UMainMenu_ExitButtons_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UMainMenu_ExitButtons_C>();
	}
};
static_assert(alignof(UMainMenu_ExitButtons_C) == 0x000008, "Wrong alignment on UMainMenu_ExitButtons_C");
static_assert(sizeof(UMainMenu_ExitButtons_C) == 0x0002A8, "Wrong size on UMainMenu_ExitButtons_C");
static_assert(offsetof(UMainMenu_ExitButtons_C, UberGraphFrame) == 0x000260, "Member 'UMainMenu_ExitButtons_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, ButtonEXIT) == 0x000268, "Member 'UMainMenu_ExitButtons_C::ButtonEXIT' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, HoverCheckArea) == 0x000270, "Member 'UMainMenu_ExitButtons_C::HoverCheckArea' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, Line) == 0x000278, "Member 'UMainMenu_ExitButtons_C::Line' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, MainMenu_Button_Development) == 0x000280, "Member 'UMainMenu_ExitButtons_C::MainMenu_Button_Development' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, Was_hovered) == 0x000288, "Member 'UMainMenu_ExitButtons_C::Was_hovered' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, REF_MainMenu) == 0x000290, "Member 'UMainMenu_ExitButtons_C::REF_MainMenu' has a wrong offset!");
static_assert(offsetof(UMainMenu_ExitButtons_C, OnUnhovered) == 0x000298, "Member 'UMainMenu_ExitButtons_C::OnUnhovered' has a wrong offset!");

}

