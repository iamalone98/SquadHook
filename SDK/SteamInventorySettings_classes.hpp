#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SteamInventorySettings

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass SteamInventorySettings.SteamInventorySettings_C
// 0x0050 (0x02B0 - 0x0260)
class USteamInventorySettings_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Image_4;                                           // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    MainPatchesTab;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UModelRenderPanel_C*                    ModelRenderPanel;                                  // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_MainMenuButton_C*                    PatchesTab;                                        // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox;                                         // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SelectedItemDesc;                                  // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SelectedItemName;                                  // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UListView*                              SteamItemsList;                                    // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	int32                                         Mode;                                              // 0x02A8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_SteamInventorySettings(int32 EntryPoint);
	void BndEvt__MainPatchesTab_K2Node_ComponentBoundEvent_2_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void BndEvt__MainMenu_Button_1_K2Node_ComponentBoundEvent_1_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void OnItemHovered(class UObject* Item, bool bIsHovered);
	void UpdateItems();
	void RefreshInventory();
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SteamInventorySettings_C">();
	}
	static class USteamInventorySettings_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USteamInventorySettings_C>();
	}
};
static_assert(alignof(USteamInventorySettings_C) == 0x000008, "Wrong alignment on USteamInventorySettings_C");
static_assert(sizeof(USteamInventorySettings_C) == 0x0002B0, "Wrong size on USteamInventorySettings_C");
static_assert(offsetof(USteamInventorySettings_C, UberGraphFrame) == 0x000260, "Member 'USteamInventorySettings_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, Image_4) == 0x000268, "Member 'USteamInventorySettings_C::Image_4' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, MainPatchesTab) == 0x000270, "Member 'USteamInventorySettings_C::MainPatchesTab' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, ModelRenderPanel) == 0x000278, "Member 'USteamInventorySettings_C::ModelRenderPanel' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, PatchesTab) == 0x000280, "Member 'USteamInventorySettings_C::PatchesTab' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, ScrollBox) == 0x000288, "Member 'USteamInventorySettings_C::ScrollBox' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, SelectedItemDesc) == 0x000290, "Member 'USteamInventorySettings_C::SelectedItemDesc' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, SelectedItemName) == 0x000298, "Member 'USteamInventorySettings_C::SelectedItemName' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, SteamItemsList) == 0x0002A0, "Member 'USteamInventorySettings_C::SteamItemsList' has a wrong offset!");
static_assert(offsetof(USteamInventorySettings_C, Mode) == 0x0002A8, "Member 'USteamInventorySettings_C::Mode' has a wrong offset!");

}

