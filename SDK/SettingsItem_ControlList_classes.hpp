#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SettingsItem_ControlList

#include "Basic.hpp"

#include "InputCore_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SettingsItem_ControlList.SettingsItem_ControlList_C
// 0x0108 (0x0368 - 0x0260)
class USettingsItem_ControlList_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_0;                                          // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_4;                                          // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGlowingButton_12_C*                    NewKey_Alternative;                                // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGlowingButton_12_C*                    NewKey_JoystickGamepad;                            // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGlowingButton_12_C*                    NewKey_Primary;                                    // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ActionName;                                     // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FName                                   ActionName;                                        // 0x0298(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class UControlsWindow_C*                      ControlsWindow;                                    // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         CapturingKey;                                      // 0x02A8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Axis;                                              // 0x02AC(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          NegativeAxis;                                      // 0x02AD(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_319A[0x2];                                     // 0x02AE(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class FText                                   FriendlyName;                                      // 0x02B0(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	TMap<class FString, class FText>              InputKeyMap;                                       // 0x02C8(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	TSet<struct FKey>                             BlacklistInputs;                                   // 0x0318(0x0050)(Edit, BlueprintVisible, ExposeOnSpawn)

public:
	void ExecuteUbergraph_SettingsItem_ControlList(int32 EntryPoint);
	void BndEvt__Button_4_K2Node_ComponentBoundEvent_244_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_4_K2Node_ComponentBoundEvent_223_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__NewKey_JoystickGamepad_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UGlowingButton_12_C* Button);
	void BndEvt__NewKey_JoystickGamepad_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature(bool bHovered);
	void BndEvt__NewKey2_K2Node_ComponentBoundEvent_364_OnClicked__DelegateSignature(bool bSelected, class UGlowingButton_12_C* Button);
	void BndEvt__NewKey1_K2Node_ComponentBoundEvent_355_OnClicked__DelegateSignature(bool bSelected, class UGlowingButton_12_C* Button);
	void OnInput_Event_0(const struct FKey& InputKey);
	void BindInputCaptureEvents();
	void BndEvt__NewKey2_K2Node_ComponentBoundEvent_1_OnHover__DelegateSignature(bool bHovered);
	void BndEvt__NewKey1_K2Node_ComponentBoundEvent_0_OnHover__DelegateSignature(bool bHovered);
	void Init(const class UControlsWindow_C* Param_ControlsWindow, class FName Param_ActionName, const class FText& Param_FriendlyName);
	void UpdateKeys();
	void StartInputCapture(int32 KeyId);
	void FinishInputCapture(const struct FKey& NewKey);
	void OnInput(const struct FKey& InputKey);
	struct FEventReply OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void RebindActionKey(const struct FKey& Key);
	void RebindAxisKey(const struct FKey& Key);
	void Get_Axis_Map_to_Edit(struct FInputAxisKeyMapping* Map, bool* Valid);
	void Is_Action_Key_Valid(bool* Key_Is_Valid);

	void GetMappedActionKeys(TArray<struct FKey>* Keys) const;
	void GetMappedAxisKeys(TArray<struct FKey>* Keys) const;
	void TranslateKey(const struct FKey& Key, class FText* Text) const;
	void GetMappedKeys(TArray<struct FKey>* Keys) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SettingsItem_ControlList_C">();
	}
	static class USettingsItem_ControlList_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USettingsItem_ControlList_C>();
	}
};
static_assert(alignof(USettingsItem_ControlList_C) == 0x000008, "Wrong alignment on USettingsItem_ControlList_C");
static_assert(sizeof(USettingsItem_ControlList_C) == 0x000368, "Wrong size on USettingsItem_ControlList_C");
static_assert(offsetof(USettingsItem_ControlList_C, UberGraphFrame) == 0x000260, "Member 'USettingsItem_ControlList_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, Border_0) == 0x000268, "Member 'USettingsItem_ControlList_C::Border_0' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, Button_4) == 0x000270, "Member 'USettingsItem_ControlList_C::Button_4' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, NewKey_Alternative) == 0x000278, "Member 'USettingsItem_ControlList_C::NewKey_Alternative' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, NewKey_JoystickGamepad) == 0x000280, "Member 'USettingsItem_ControlList_C::NewKey_JoystickGamepad' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, NewKey_Primary) == 0x000288, "Member 'USettingsItem_ControlList_C::NewKey_Primary' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, TB_ActionName) == 0x000290, "Member 'USettingsItem_ControlList_C::TB_ActionName' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, ActionName) == 0x000298, "Member 'USettingsItem_ControlList_C::ActionName' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, ControlsWindow) == 0x0002A0, "Member 'USettingsItem_ControlList_C::ControlsWindow' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, CapturingKey) == 0x0002A8, "Member 'USettingsItem_ControlList_C::CapturingKey' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, Axis) == 0x0002AC, "Member 'USettingsItem_ControlList_C::Axis' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, NegativeAxis) == 0x0002AD, "Member 'USettingsItem_ControlList_C::NegativeAxis' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, FriendlyName) == 0x0002B0, "Member 'USettingsItem_ControlList_C::FriendlyName' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, InputKeyMap) == 0x0002C8, "Member 'USettingsItem_ControlList_C::InputKeyMap' has a wrong offset!");
static_assert(offsetof(USettingsItem_ControlList_C, BlacklistInputs) == 0x000318, "Member 'USettingsItem_ControlList_C::BlacklistInputs' has a wrong offset!");

}

