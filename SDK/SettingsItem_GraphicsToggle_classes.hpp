#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_GraphicsToggle

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "ColoredTextStruct_structs.hpp"
#include "W_BaseSettingOption_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SettingsItem_GraphicsToggle.SettingsItem_GraphicsToggle_C
// 0x0088 (0x0328 - 0x02A0)
class USettingsItem_GraphicsToggle_C final : public UW_BaseSettingOption_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_SettingsItem_GraphicsToggle_C;      // 0x02A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                GlobalButton;                                      // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalButtonBox;                               // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Title;                                          // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   SettingName;                                       // 0x02C0(0x0018)(Edit, BlueprintVisible)
	TArray<class FText>                           ButtonNames;                                       // 0x02D8(0x0010)(Edit, BlueprintVisible)
	int32                                         SelectedButton;                                    // 0x02E8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bHovered;                                          // 0x02EC(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bConstructed;                                      // 0x02ED(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4387[0x2];                                     // 0x02EE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         Tag;                                               // 0x02F0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4388[0x4];                                     // 0x02F4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnButtonClick;                                     // 0x02F8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class USetting_Button_C*>              My_Buttons;                                        // 0x0308(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	TArray<struct FColoredTextStruct>             ToolTipTexts;                                      // 0x0318(0x0010)(Edit, BlueprintVisible)

public:
	void OnButtonClick__DelegateSignature(int32 ButtonNumber, class USettingsItem_GraphicsToggle_C* ToggleItem);
	void ExecuteUbergraph_SettingsItem_GraphicsToggle(int32 EntryPoint);
	void On_Button_Clicked(bool bSelected, class USetting_Button_C* Button);
	void Create_Buttons();
	void PreConstruct(bool IsDesignTime);
	void Construct();
	void SetSelected(int32 Param_Index);
	struct FSlateBrush GetBrush();
	class USetting_Button_C* Setup_Button(const class FText& ButtonText, const struct FColoredTextStruct& Inherit_Text);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SettingsItem_GraphicsToggle_C">();
	}
	static class USettingsItem_GraphicsToggle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USettingsItem_GraphicsToggle_C>();
	}
};
static_assert(alignof(USettingsItem_GraphicsToggle_C) == 0x000008, "Wrong alignment on USettingsItem_GraphicsToggle_C");
static_assert(sizeof(USettingsItem_GraphicsToggle_C) == 0x000328, "Wrong size on USettingsItem_GraphicsToggle_C");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, UberGraphFrame_SettingsItem_GraphicsToggle_C) == 0x0002A0, "Member 'USettingsItem_GraphicsToggle_C::UberGraphFrame_SettingsItem_GraphicsToggle_C' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, GlobalButton) == 0x0002A8, "Member 'USettingsItem_GraphicsToggle_C::GlobalButton' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, HorizontalButtonBox) == 0x0002B0, "Member 'USettingsItem_GraphicsToggle_C::HorizontalButtonBox' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, TB_Title) == 0x0002B8, "Member 'USettingsItem_GraphicsToggle_C::TB_Title' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, SettingName) == 0x0002C0, "Member 'USettingsItem_GraphicsToggle_C::SettingName' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, ButtonNames) == 0x0002D8, "Member 'USettingsItem_GraphicsToggle_C::ButtonNames' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, SelectedButton) == 0x0002E8, "Member 'USettingsItem_GraphicsToggle_C::SelectedButton' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, bHovered) == 0x0002EC, "Member 'USettingsItem_GraphicsToggle_C::bHovered' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, bConstructed) == 0x0002ED, "Member 'USettingsItem_GraphicsToggle_C::bConstructed' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, Tag) == 0x0002F0, "Member 'USettingsItem_GraphicsToggle_C::Tag' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, OnButtonClick) == 0x0002F8, "Member 'USettingsItem_GraphicsToggle_C::OnButtonClick' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, My_Buttons) == 0x000308, "Member 'USettingsItem_GraphicsToggle_C::My_Buttons' has a wrong offset!");
static_assert(offsetof(USettingsItem_GraphicsToggle_C, ToolTipTexts) == 0x000318, "Member 'USettingsItem_GraphicsToggle_C::ToolTipTexts' has a wrong offset!");

}

