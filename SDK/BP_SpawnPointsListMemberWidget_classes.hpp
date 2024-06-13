#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SpawnPointsListMemberWidget

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_SpawnPointsListMemberWidget.BP_SpawnPointsListMemberWidget_C
// 0x00A0 (0x0378 - 0x02D8)
class UBP_SpawnPointsListMemberWidget_C final : public USQCoreStateSpawnPointsListWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02D8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Image_161;                                         // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Overlay_2;                                         // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMainMenu_Button_C*                     SpawnButton;                                       // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Time;                                           // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ASQGameSpawn*                           SpawnPoint;                                        // 0x0300(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	struct FLinearColor                           HoveredColor;                                      // 0x0308(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           SelectedColor;                                     // 0x0318(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           NotSelectedColor;                                  // 0x0328(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   LocationText;                                      // 0x0338(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class FText                                   TypeText;                                          // 0x0350(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	class ABP_PlayerController_C*                 My_PC;                                             // 0x0368(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           UpdateTextTimer;                                   // 0x0370(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_SpawnPointsListMemberWidget(int32 EntryPoint);
	void UpdateTextLooping();
	void OnInitialized();
	void OnActivatedTimeStampChanged();
	void OnSiegedChanged();
	void OnSpawningEnabledChanged();
	void BndEvt__SpawnButton_K2Node_ComponentBoundEvent_1_OnDoubleClicked__DelegateSignature();
	void Construct();
	void BndEvt__MainMenu_Button_K2Node_ComponentBoundEvent_0_OnClicked__DelegateSignature(bool bSelected, class UMainMenu_Button_C* Button);
	void OnSpawnPointTypeChanged();
	void OnSpawnPointLocationChanged();
	void OnIsSelectedChanged();
	void UpdateText();
	void UpdateLocation();
	void UpdateType();
	void UpdateVisibility();
	void GetRemainingActivatingTime(float* RemainingTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SpawnPointsListMemberWidget_C">();
	}
	static class UBP_SpawnPointsListMemberWidget_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SpawnPointsListMemberWidget_C>();
	}
};
static_assert(alignof(UBP_SpawnPointsListMemberWidget_C) == 0x000008, "Wrong alignment on UBP_SpawnPointsListMemberWidget_C");
static_assert(sizeof(UBP_SpawnPointsListMemberWidget_C) == 0x000378, "Wrong size on UBP_SpawnPointsListMemberWidget_C");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, UberGraphFrame) == 0x0002D8, "Member 'UBP_SpawnPointsListMemberWidget_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, Image_161) == 0x0002E0, "Member 'UBP_SpawnPointsListMemberWidget_C::Image_161' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, Overlay_2) == 0x0002E8, "Member 'UBP_SpawnPointsListMemberWidget_C::Overlay_2' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, SpawnButton) == 0x0002F0, "Member 'UBP_SpawnPointsListMemberWidget_C::SpawnButton' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, TB_Time) == 0x0002F8, "Member 'UBP_SpawnPointsListMemberWidget_C::TB_Time' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, SpawnPoint) == 0x000300, "Member 'UBP_SpawnPointsListMemberWidget_C::SpawnPoint' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, HoveredColor) == 0x000308, "Member 'UBP_SpawnPointsListMemberWidget_C::HoveredColor' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, SelectedColor) == 0x000318, "Member 'UBP_SpawnPointsListMemberWidget_C::SelectedColor' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, NotSelectedColor) == 0x000328, "Member 'UBP_SpawnPointsListMemberWidget_C::NotSelectedColor' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, LocationText) == 0x000338, "Member 'UBP_SpawnPointsListMemberWidget_C::LocationText' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, TypeText) == 0x000350, "Member 'UBP_SpawnPointsListMemberWidget_C::TypeText' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, My_PC) == 0x000368, "Member 'UBP_SpawnPointsListMemberWidget_C::My_PC' has a wrong offset!");
static_assert(offsetof(UBP_SpawnPointsListMemberWidget_C, UpdateTextTimer) == 0x000370, "Member 'UBP_SpawnPointsListMemberWidget_C::UpdateTextTimer' has a wrong offset!");

}
