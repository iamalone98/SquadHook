#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Slider

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "ColoredTextRangeStruct_structs.hpp"
#include "UMG_classes.hpp"
#include "SlateCore_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_Slider.W_Slider_C
// 0x0130 (0x0390 - 0x0260)
class UW_Slider_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USlider*                                BaseSlider;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_225;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_641;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UEditableText*                          SliderValue;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               Spacer;                                            // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         SliderMin;                                         // 0x0290(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SliderMax;                                         // 0x0294(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MinValue;                                          // 0x0298(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxValue;                                          // 0x029C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Value;                                             // 0x02A0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         MinFractionDigits;                                 // 0x02A4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         MaxFractionDigits;                                 // 0x02A8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bConstructed;                                      // 0x02AC(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bIsPercentage;                                     // 0x02AD(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3177[0x2];                                     // 0x02AE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         StepSize;                                          // 0x02B0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bStepByPower;                                      // 0x02B4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3178[0x3];                                     // 0x02B5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Power;                                             // 0x02B8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3179[0x4];                                     // 0x02BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TMap<struct FLinearColor, struct FColoredTextRangeStruct> ColorRange;                                        // 0x02C0(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FLinearColor                           TextColor;                                         // 0x0310(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CachedSliderText;                                  // 0x0320(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	float                                         TextBoxSize;                                       // 0x0338(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          CanEditTextField;                                  // 0x033C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_317A[0x3];                                     // 0x033D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnValueChanged;                                    // 0x0340(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnCaptureEnd;                                      // 0x0350(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	float                                         Spacing;                                           // 0x0360(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           SliderColor;                                       // 0x0364(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           SliderHandleColor;                                 // 0x0374(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              HandleSize;                                        // 0x0384(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SliderThickness;                                   // 0x038C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void OnValueChanged__DelegateSignature(float NewParam);
	void OnCaptureEnd__DelegateSignature(float Param_Value);
	void ExecuteUbergraph_W_Slider(int32 EntryPoint);
	void BndEvt__BaseSlider_K2Node_ComponentBoundEvent_3_OnMouseCaptureEndEvent__DelegateSignature();
	void BndEvt__SliderValue_K2Node_ComponentBoundEvent_2_OnEditableTextCommittedEvent__DelegateSignature(const class FText& Text, ETextCommit CommitMethod);
	void BndEvt__SliderValue_K2Node_ComponentBoundEvent_1_OnEditableTextChangedEvent__DelegateSignature(const class FText& Text);
	void BndEvt__BaseSlider_K2Node_ComponentBoundEvent_0_OnFloatValueChangedEvent__DelegateSignature(float Param_Value);
	void Construct();
	void PreConstruct(bool IsDesignTime);
	void SetValue(float Param_Value);
	void UpdateSliderTextValue();
	void UpdateSliderValue();
	void RemovePercentage(const class FText& InText, class FText* OutText);
	void GetTextColor(float Param_Value, struct FLinearColor* Param_TextColor, class FText* WarningText);
	void UpdateStyle();
	float RoundingToPower(float InputPin);
	void UpdateSliderStyle(const struct FSliderStyle& WidgetStyle, struct FSliderStyle* NewParam);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_Slider_C">();
	}
	static class UW_Slider_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_Slider_C>();
	}
};
static_assert(alignof(UW_Slider_C) == 0x000008, "Wrong alignment on UW_Slider_C");
static_assert(sizeof(UW_Slider_C) == 0x000390, "Wrong size on UW_Slider_C");
static_assert(offsetof(UW_Slider_C, UberGraphFrame) == 0x000260, "Member 'UW_Slider_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, BaseSlider) == 0x000268, "Member 'UW_Slider_C::BaseSlider' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, Border_225) == 0x000270, "Member 'UW_Slider_C::Border_225' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SizeBox_641) == 0x000278, "Member 'UW_Slider_C::SizeBox_641' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderValue) == 0x000280, "Member 'UW_Slider_C::SliderValue' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, Spacer) == 0x000288, "Member 'UW_Slider_C::Spacer' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderMin) == 0x000290, "Member 'UW_Slider_C::SliderMin' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderMax) == 0x000294, "Member 'UW_Slider_C::SliderMax' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, MinValue) == 0x000298, "Member 'UW_Slider_C::MinValue' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, MaxValue) == 0x00029C, "Member 'UW_Slider_C::MaxValue' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, Value) == 0x0002A0, "Member 'UW_Slider_C::Value' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, MinFractionDigits) == 0x0002A4, "Member 'UW_Slider_C::MinFractionDigits' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, MaxFractionDigits) == 0x0002A8, "Member 'UW_Slider_C::MaxFractionDigits' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, bConstructed) == 0x0002AC, "Member 'UW_Slider_C::bConstructed' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, bIsPercentage) == 0x0002AD, "Member 'UW_Slider_C::bIsPercentage' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, StepSize) == 0x0002B0, "Member 'UW_Slider_C::StepSize' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, bStepByPower) == 0x0002B4, "Member 'UW_Slider_C::bStepByPower' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, Power) == 0x0002B8, "Member 'UW_Slider_C::Power' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, ColorRange) == 0x0002C0, "Member 'UW_Slider_C::ColorRange' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, TextColor) == 0x000310, "Member 'UW_Slider_C::TextColor' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, CachedSliderText) == 0x000320, "Member 'UW_Slider_C::CachedSliderText' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, TextBoxSize) == 0x000338, "Member 'UW_Slider_C::TextBoxSize' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, CanEditTextField) == 0x00033C, "Member 'UW_Slider_C::CanEditTextField' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, OnValueChanged) == 0x000340, "Member 'UW_Slider_C::OnValueChanged' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, OnCaptureEnd) == 0x000350, "Member 'UW_Slider_C::OnCaptureEnd' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, Spacing) == 0x000360, "Member 'UW_Slider_C::Spacing' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderColor) == 0x000364, "Member 'UW_Slider_C::SliderColor' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderHandleColor) == 0x000374, "Member 'UW_Slider_C::SliderHandleColor' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, HandleSize) == 0x000384, "Member 'UW_Slider_C::HandleSize' has a wrong offset!");
static_assert(offsetof(UW_Slider_C, SliderThickness) == 0x00038C, "Member 'UW_Slider_C::SliderThickness' has a wrong offset!");

}
