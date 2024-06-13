#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_Slider

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "ColoredTextRangeStruct_structs.hpp"
#include "W_BaseSettingOption_classes.hpp"
#include "SlateCore_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SettingsItem_Slider.SettingsItem_Slider_C
// 0x0178 (0x0418 - 0x02A0)
class USettingsItem_Slider_C final : public UW_BaseSettingOption_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_SettingsItem_Slider_C;              // 0x02A0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                Button_0;                                          // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_0;                                   // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_Label;                                     // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_Output;                                    // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_Slider;                                    // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USlider*                                Slider;                                            // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UEditableText*                          SliderText;                                        // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                SliderTextBorder;                                  // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Title;                                          // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             WarningMessage;                                    // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   SettingName;                                       // 0x02F8(0x0018)(Edit, BlueprintVisible)
	float                                         SliderMin;                                         // 0x0310(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SliderMax;                                         // 0x0314(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MinValue;                                          // 0x0318(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxValue;                                          // 0x031C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Value;                                             // 0x0320(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         MinFractionDigits;                                 // 0x0324(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         MaxFractionDigits;                                 // 0x0328(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2740[0x4];                                     // 0x032C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   CachedSliderText;                                  // 0x0330(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             OnValueChanged;                                    // 0x0348(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          bConstructed;                                      // 0x0358(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bIsPercentage;                                     // 0x0359(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2741[0x2];                                     // 0x035A(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	struct FLinearColor                           Regular_Color;                                     // 0x035C(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Hovered_Color;                                     // 0x036C(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Pressed_Color;                                     // 0x037C(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_2742[0x4];                                     // 0x038C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnCaptureEnd;                                      // 0x0390(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	float                                         TextBoxSize;                                       // 0x03A0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         StepSize;                                          // 0x03A4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          StepByPower;                                       // 0x03A8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, AdvancedDisplay)
	uint8                                         Pad_2743[0x3];                                     // 0x03A9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Power;                                             // 0x03AC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, AdvancedDisplay, HasGetValueTypeHash)
	bool                                          CanEditTextField;                                  // 0x03B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2744[0x7];                                     // 0x03B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TMap<struct FLinearColor, struct FColoredTextRangeStruct> ColorRange;                                        // 0x03B8(0x0050)(Edit, BlueprintVisible, AdvancedDisplay)
	float                                         DefaultValue;                                      // 0x0408(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         SliderBoxSize;                                     // 0x040C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         OutputBoxSize;                                     // 0x0410(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void OnValueChanged__DelegateSignature(float Param_Value);
	void OnCaptureEnd__DelegateSignature(float Param_Value);
	void ExecuteUbergraph_SettingsItem_Slider(int32 EntryPoint);
	void SetSettingValue(class FName Setting_Name, const class FString& Param_Value);
	void BndEvt__Slider_K2Node_ComponentBoundEvent_361_OnFloatValueChangedEvent__DelegateSignature(float Param_Value);
	void BndEvt__Slider_K2Node_ComponentBoundEvent_15_OnMouseCaptureEndEvent__DelegateSignature();
	void PreConstruct(bool IsDesignTime);
	void Construct();
	void BndEvt__SliderText_K2Node_ComponentBoundEvent_275_OnEditableTextCommittedEvent__DelegateSignature(const class FText& Text, ETextCommit CommitMethod);
	void BndEvt__SliderText_K2Node_ComponentBoundEvent_191_OnEditableTextChangedEvent__DelegateSignature(const class FText& Text);
	void SetValue(float Param_Value);
	void UpdateSliderTextValue();
	void UpdateSliderValue();
	struct FSlateBrush Get_SpacerImg_Brush_0();
	void GetTextColor(float Param_Value, struct FLinearColor* TextColor, class FText* WarningText);
	void UpdateTextStyle(float Param_Value);
	float RoundingToPower(float A);
	void SetSliderText(const class FText& NewText);

	void RemovePercentage(const class FText& InText, class FText* OutText) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SettingsItem_Slider_C">();
	}
	static class USettingsItem_Slider_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USettingsItem_Slider_C>();
	}
};
static_assert(alignof(USettingsItem_Slider_C) == 0x000008, "Wrong alignment on USettingsItem_Slider_C");
static_assert(sizeof(USettingsItem_Slider_C) == 0x000418, "Wrong size on USettingsItem_Slider_C");
static_assert(offsetof(USettingsItem_Slider_C, UberGraphFrame_SettingsItem_Slider_C) == 0x0002A0, "Member 'USettingsItem_Slider_C::UberGraphFrame_SettingsItem_Slider_C' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Button_0) == 0x0002A8, "Member 'USettingsItem_Slider_C::Button_0' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, HorizontalBox_0) == 0x0002B0, "Member 'USettingsItem_Slider_C::HorizontalBox_0' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SizeBox_Label) == 0x0002B8, "Member 'USettingsItem_Slider_C::SizeBox_Label' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SizeBox_Output) == 0x0002C0, "Member 'USettingsItem_Slider_C::SizeBox_Output' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SizeBox_Slider) == 0x0002C8, "Member 'USettingsItem_Slider_C::SizeBox_Slider' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Slider) == 0x0002D0, "Member 'USettingsItem_Slider_C::Slider' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SliderText) == 0x0002D8, "Member 'USettingsItem_Slider_C::SliderText' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SliderTextBorder) == 0x0002E0, "Member 'USettingsItem_Slider_C::SliderTextBorder' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, TB_Title) == 0x0002E8, "Member 'USettingsItem_Slider_C::TB_Title' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, WarningMessage) == 0x0002F0, "Member 'USettingsItem_Slider_C::WarningMessage' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SettingName) == 0x0002F8, "Member 'USettingsItem_Slider_C::SettingName' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SliderMin) == 0x000310, "Member 'USettingsItem_Slider_C::SliderMin' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SliderMax) == 0x000314, "Member 'USettingsItem_Slider_C::SliderMax' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, MinValue) == 0x000318, "Member 'USettingsItem_Slider_C::MinValue' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, MaxValue) == 0x00031C, "Member 'USettingsItem_Slider_C::MaxValue' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Value) == 0x000320, "Member 'USettingsItem_Slider_C::Value' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, MinFractionDigits) == 0x000324, "Member 'USettingsItem_Slider_C::MinFractionDigits' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, MaxFractionDigits) == 0x000328, "Member 'USettingsItem_Slider_C::MaxFractionDigits' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, CachedSliderText) == 0x000330, "Member 'USettingsItem_Slider_C::CachedSliderText' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, OnValueChanged) == 0x000348, "Member 'USettingsItem_Slider_C::OnValueChanged' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, bConstructed) == 0x000358, "Member 'USettingsItem_Slider_C::bConstructed' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, bIsPercentage) == 0x000359, "Member 'USettingsItem_Slider_C::bIsPercentage' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Regular_Color) == 0x00035C, "Member 'USettingsItem_Slider_C::Regular_Color' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Hovered_Color) == 0x00036C, "Member 'USettingsItem_Slider_C::Hovered_Color' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Pressed_Color) == 0x00037C, "Member 'USettingsItem_Slider_C::Pressed_Color' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, OnCaptureEnd) == 0x000390, "Member 'USettingsItem_Slider_C::OnCaptureEnd' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, TextBoxSize) == 0x0003A0, "Member 'USettingsItem_Slider_C::TextBoxSize' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, StepSize) == 0x0003A4, "Member 'USettingsItem_Slider_C::StepSize' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, StepByPower) == 0x0003A8, "Member 'USettingsItem_Slider_C::StepByPower' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, Power) == 0x0003AC, "Member 'USettingsItem_Slider_C::Power' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, CanEditTextField) == 0x0003B0, "Member 'USettingsItem_Slider_C::CanEditTextField' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, ColorRange) == 0x0003B8, "Member 'USettingsItem_Slider_C::ColorRange' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, DefaultValue) == 0x000408, "Member 'USettingsItem_Slider_C::DefaultValue' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, SliderBoxSize) == 0x00040C, "Member 'USettingsItem_Slider_C::SliderBoxSize' has a wrong offset!");
static_assert(offsetof(USettingsItem_Slider_C, OutputBoxSize) == 0x000410, "Member 'USettingsItem_Slider_C::OutputBoxSize' has a wrong offset!");

}

