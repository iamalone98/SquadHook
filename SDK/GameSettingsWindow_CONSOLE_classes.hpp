#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: GameSettingsWindow_CONSOLE

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "ScreenResolutionStruct_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass GameSettingsWindow_CONSOLE.GameSettingsWindow_CONSOLE_C
// 0x0170 (0x03D0 - 0x0260)
class UGameSettingsWindow_CONSOLE_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USettingsComboboxItem_C*                ADSMode;                                           // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                CrouchMode;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 FOV;                                               // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                FreelookMode;                                      // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 HelicopterPitchSensitivity;                        // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 HelicopterRollSensitivity;                         // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_2;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_4;                                           // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_5;                                           // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_6;                                           // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                LeanMode;                                          // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TextBox_C*                PLAYERPREFIX;                                      // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox;                                         // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier12XSensitivity;                             // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier1XSensitivity;                              // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier2XSensitivity;                              // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier3XSensitivity;                              // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier4XSensitivity;                              // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier6XSensitivity;                              // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Soldier8XSensitivity;                              // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 SoldierNonAdsSensitivity;                          // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsComboboxItem_C*                SprintMode;                                        // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextSOLDIERSENSITIVITYMULTIPLIERS;                 // 0x0320(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                ToggleDoubleMinusTapWalk;                          // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                ToggleFreelookRecenter;                            // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                ToggleHelicopterInvertMousePitch;                  // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                ToggleJumpUncrouch;                                // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                ToggleJumpUnprone;                                 // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_TickBox_C*                UseSensitivityScaling;                             // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 VehicleLongSensitivity;                            // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 VehicleSensitivity;                                // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 VehicleShortSensitivity;                           // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<struct FScreenResolutionStruct>        ScreenResolutions;                                 // 0x0370(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	TArray<struct FScreenResolutionStruct>        ValidResolutions;                                  // 0x0380(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          bConstructed;                                      // 0x0390(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3551[0x7];                                     // 0x0391(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Reset_Appdata_OnClicked;                           // 0x0398(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	struct FLinearColor                           SelectedColor;                                     // 0x03A8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           UnselectedColor_;                                  // 0x03B8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USaveData_UI_C*                         Current_UI_Save;                                   // 0x03C8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void Reset_Appdata_OnClicked__DelegateSignature();
	void ExecuteUbergraph_GameSettingsWindow_CONSOLE(int32 EntryPoint);
	void BndEvt__GameSettingsWindow_Soldier4XSensitivity_K2Node_ComponentBoundEvent_21_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__GameSettingsWindow_Soldier3XSensitivity_K2Node_ComponentBoundEvent_16_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__GameSettingsWindow_Soldier8XSensitivity_K2Node_ComponentBoundEvent_10_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__GameSettingsWindow_Soldier2XSensitivity_K2Node_ComponentBoundEvent_8_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SoldierLongSensitivity_K2Node_ComponentBoundEvent_746_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SoldierMediumSensitivity_K2Node_ComponentBoundEvent_708_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SoldierShortSensitivity_K2Node_ComponentBoundEvent_703_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SprintMode_K2Node_ComponentBoundEvent_14_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__LeanMode_K2Node_ComponentBoundEvent_12_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__FreelookMode_K2Node_ComponentBoundEvent_11_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__ADSMode_K2Node_ComponentBoundEvent_9_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__CrouchMode_K2Node_ComponentBoundEvent_5_OnValueChanged__DelegateSignature(const class FString& Option, int32 Param_Index);
	void BndEvt__ToggleHelicopterInvertMousePitch_K2Node_ComponentBoundEvent_7_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__HelicopterRollSensitivity_K2Node_ComponentBoundEvent_6_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__HelicopterPitchSensitivity_K2Node_ComponentBoundEvent_2_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SettingsItem_Slider_C_0_K2Node_ComponentBoundEvent_164_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__Keyboardhilite_K2Node_ComponentBoundEvent_1305_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__VehicleSensitivity_K2Node_ComponentBoundEvent_411_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__SoldierSensitivity_K2Node_ComponentBoundEvent_406_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__VehicleMediumSensitivity_K2Node_ComponentBoundEvent_828_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__VehicleShortSensitivity_K2Node_ComponentBoundEvent_786_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__ToggleFreelookRecenter_K2Node_ComponentBoundEvent_143_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void Construct();
	void BndEvt__ToggleMouseSmooth_K2Node_ComponentBoundEvent_21_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__ToggleJumpUnprone_K2Node_ComponentBoundEvent_18_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__ToggleJumpUncrouch_K2Node_ComponentBoundEvent_17_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__ToggleInvertY_K2Node_ComponentBoundEvent_15_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__ToggleDoubleTapWalk_K2Node_ComponentBoundEvent_13_OnClicked__DelegateSignature(bool bSelected, class USettingsItem_TickBox_C* Button);
	void BndEvt__PLAYERPREFIX_K2Node_ComponentBoundEvent_31_OnValueChanged__DelegateSignature(const class FText& NewText);
	void BndEvt__FOV_K2Node_ComponentBoundEvent_19_OnValueChanged__DelegateSignature(float Value);
	void UpdateButtons();
	class UWidget* Get_ToggleFreelookRecenter_ToolTipWidget_0();
	class UWidget* Get_PLAYERPREFIX_ToolTipWidget_0();
	class UWidget* Get_ToggleJumpUncrouch_ToolTipWidget_0();
	class UWidget* Get_ToggleJumpUnprone_ToolTipWidget_0();
	class UWidget* Get_ToggleDoubleTapWalk_ToolTipWidget_0();
	void UpdateZoomSensitivitySliders();
	struct FLinearColor Get_IndividualMultipliers_Color();
	class UWidget* Get_SoldierShortSensitivity_ToolTipWidget_0();
	class UWidget* Get_SoldierMediumSensitivity_ToolTipWidget_0();
	class UWidget* Get_SoldierLongSensitivity_ToolTipWidget_0();
	class UWidget* Get_VehicleShortSensitivity_ToolTipWidget_0();
	class UWidget* Get_VehicleLongSensitivity_ToolTipWidget_0();
	class UWidget* Get_SoldierNonAdsSensitivity_ToolTipWidget_0();
	class UWidget* Get_UseSensitivityScaling_ToolTipWidget_0();
	class UWidget* Get_HelicopterPitchSensitivity_ToolTipWidget_0();
	class UWidget* Get_HelicopterRollSensitivity_ToolTipWidget_0();
	class UWidget* Get_ToggleHelicopterInvertMousePitch_ToolTipWidget_0();
	void UpdateStreamerLevel(ESQStreamerModeLevel Enum, bool NewState);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"GameSettingsWindow_CONSOLE_C">();
	}
	static class UGameSettingsWindow_CONSOLE_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UGameSettingsWindow_CONSOLE_C>();
	}
};
static_assert(alignof(UGameSettingsWindow_CONSOLE_C) == 0x000008, "Wrong alignment on UGameSettingsWindow_CONSOLE_C");
static_assert(sizeof(UGameSettingsWindow_CONSOLE_C) == 0x0003D0, "Wrong size on UGameSettingsWindow_CONSOLE_C");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, UberGraphFrame) == 0x000260, "Member 'UGameSettingsWindow_CONSOLE_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ADSMode) == 0x000268, "Member 'UGameSettingsWindow_CONSOLE_C::ADSMode' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, CrouchMode) == 0x000270, "Member 'UGameSettingsWindow_CONSOLE_C::CrouchMode' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, FOV) == 0x000278, "Member 'UGameSettingsWindow_CONSOLE_C::FOV' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, FreelookMode) == 0x000280, "Member 'UGameSettingsWindow_CONSOLE_C::FreelookMode' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, HelicopterPitchSensitivity) == 0x000288, "Member 'UGameSettingsWindow_CONSOLE_C::HelicopterPitchSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, HelicopterRollSensitivity) == 0x000290, "Member 'UGameSettingsWindow_CONSOLE_C::HelicopterRollSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Image) == 0x000298, "Member 'UGameSettingsWindow_CONSOLE_C::Image' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Image_2) == 0x0002A0, "Member 'UGameSettingsWindow_CONSOLE_C::Image_2' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Image_4) == 0x0002A8, "Member 'UGameSettingsWindow_CONSOLE_C::Image_4' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Image_5) == 0x0002B0, "Member 'UGameSettingsWindow_CONSOLE_C::Image_5' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Image_6) == 0x0002B8, "Member 'UGameSettingsWindow_CONSOLE_C::Image_6' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, LeanMode) == 0x0002C0, "Member 'UGameSettingsWindow_CONSOLE_C::LeanMode' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, PLAYERPREFIX) == 0x0002C8, "Member 'UGameSettingsWindow_CONSOLE_C::PLAYERPREFIX' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ScrollBox) == 0x0002D0, "Member 'UGameSettingsWindow_CONSOLE_C::ScrollBox' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier12XSensitivity) == 0x0002D8, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier12XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier1XSensitivity) == 0x0002E0, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier1XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier2XSensitivity) == 0x0002E8, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier2XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier3XSensitivity) == 0x0002F0, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier3XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier4XSensitivity) == 0x0002F8, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier4XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier6XSensitivity) == 0x000300, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier6XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Soldier8XSensitivity) == 0x000308, "Member 'UGameSettingsWindow_CONSOLE_C::Soldier8XSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, SoldierNonAdsSensitivity) == 0x000310, "Member 'UGameSettingsWindow_CONSOLE_C::SoldierNonAdsSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, SprintMode) == 0x000318, "Member 'UGameSettingsWindow_CONSOLE_C::SprintMode' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, TextSOLDIERSENSITIVITYMULTIPLIERS) == 0x000320, "Member 'UGameSettingsWindow_CONSOLE_C::TextSOLDIERSENSITIVITYMULTIPLIERS' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ToggleDoubleMinusTapWalk) == 0x000328, "Member 'UGameSettingsWindow_CONSOLE_C::ToggleDoubleMinusTapWalk' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ToggleFreelookRecenter) == 0x000330, "Member 'UGameSettingsWindow_CONSOLE_C::ToggleFreelookRecenter' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ToggleHelicopterInvertMousePitch) == 0x000338, "Member 'UGameSettingsWindow_CONSOLE_C::ToggleHelicopterInvertMousePitch' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ToggleJumpUncrouch) == 0x000340, "Member 'UGameSettingsWindow_CONSOLE_C::ToggleJumpUncrouch' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ToggleJumpUnprone) == 0x000348, "Member 'UGameSettingsWindow_CONSOLE_C::ToggleJumpUnprone' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, UseSensitivityScaling) == 0x000350, "Member 'UGameSettingsWindow_CONSOLE_C::UseSensitivityScaling' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, VehicleLongSensitivity) == 0x000358, "Member 'UGameSettingsWindow_CONSOLE_C::VehicleLongSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, VehicleSensitivity) == 0x000360, "Member 'UGameSettingsWindow_CONSOLE_C::VehicleSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, VehicleShortSensitivity) == 0x000368, "Member 'UGameSettingsWindow_CONSOLE_C::VehicleShortSensitivity' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ScreenResolutions) == 0x000370, "Member 'UGameSettingsWindow_CONSOLE_C::ScreenResolutions' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, ValidResolutions) == 0x000380, "Member 'UGameSettingsWindow_CONSOLE_C::ValidResolutions' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, bConstructed) == 0x000390, "Member 'UGameSettingsWindow_CONSOLE_C::bConstructed' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Reset_Appdata_OnClicked) == 0x000398, "Member 'UGameSettingsWindow_CONSOLE_C::Reset_Appdata_OnClicked' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, SelectedColor) == 0x0003A8, "Member 'UGameSettingsWindow_CONSOLE_C::SelectedColor' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, UnselectedColor_) == 0x0003B8, "Member 'UGameSettingsWindow_CONSOLE_C::UnselectedColor_' has a wrong offset!");
static_assert(offsetof(UGameSettingsWindow_CONSOLE_C, Current_UI_Save) == 0x0003C8, "Member 'UGameSettingsWindow_CONSOLE_C::Current_UI_Save' has a wrong offset!");

}
