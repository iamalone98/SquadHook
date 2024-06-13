#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: GraphicsWindow_CONSOLE

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "ScreenResolutionStruct_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass GraphicsWindow_CONSOLE.GraphicsWindow_CONSOLE_C
// 0x0048 (0x02A8 - 0x0260)
class UGraphicsWindow_CONSOLE_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USettingsItem_Slider_C*                 Brightness;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Contrast;                                          // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USettingsItem_Slider_C*                 Saturation;                                        // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox;                                         // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           SettingsLIst;                                      // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<struct FScreenResolutionStruct>        ValidResolutions;                                  // 0x0298(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_GraphicsWindow_CONSOLE(int32 EntryPoint);
	void BndEvt__SATURATION_K2Node_ComponentBoundEvent_14_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__CONTRAST_K2Node_ComponentBoundEvent_5_OnValueChanged__DelegateSignature(float Value);
	void BndEvt__BRIGHTNESS_K2Node_ComponentBoundEvent_4_OnValueChanged__DelegateSignature(float Value);
	void Construct();
	void Refresh_Settings(class FName CVarSettingName, const class FString& Value);
	void SetCVarSettings();
	void InitRefreshEvents();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"GraphicsWindow_CONSOLE_C">();
	}
	static class UGraphicsWindow_CONSOLE_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UGraphicsWindow_CONSOLE_C>();
	}
};
static_assert(alignof(UGraphicsWindow_CONSOLE_C) == 0x000008, "Wrong alignment on UGraphicsWindow_CONSOLE_C");
static_assert(sizeof(UGraphicsWindow_CONSOLE_C) == 0x0002A8, "Wrong size on UGraphicsWindow_CONSOLE_C");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, UberGraphFrame) == 0x000260, "Member 'UGraphicsWindow_CONSOLE_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, Brightness) == 0x000268, "Member 'UGraphicsWindow_CONSOLE_C::Brightness' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, Contrast) == 0x000270, "Member 'UGraphicsWindow_CONSOLE_C::Contrast' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, Image) == 0x000278, "Member 'UGraphicsWindow_CONSOLE_C::Image' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, Saturation) == 0x000280, "Member 'UGraphicsWindow_CONSOLE_C::Saturation' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, ScrollBox) == 0x000288, "Member 'UGraphicsWindow_CONSOLE_C::ScrollBox' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, SettingsLIst) == 0x000290, "Member 'UGraphicsWindow_CONSOLE_C::SettingsLIst' has a wrong offset!");
static_assert(offsetof(UGraphicsWindow_CONSOLE_C, ValidResolutions) == 0x000298, "Member 'UGraphicsWindow_CONSOLE_C::ValidResolutions' has a wrong offset!");

}
