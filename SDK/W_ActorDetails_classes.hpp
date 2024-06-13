#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ActorDetails

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ActorDetails.W_ActorDetails_C
// 0x00D8 (0x0338 - 0x0260)
class UW_ActorDetails_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                BackgroundButton;                                  // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                BTN_Possess;                                       // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_Damage;                                     // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                Button_Heal;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                ButtonDestroy;                                     // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UComboBoxString*                        CB_DamageTypes;                                    // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UComboBoxString*                        CB_VehicleComponents;                              // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USpinBox*                               DamageAmountBox;                                   // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox;                                     // 0x02A8(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         HorizontalBox_5;                                   // 0x02B0(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Health_Value;                                   // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ObjectName;                                     // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Team_Value;                                     // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VB_Damage;                                         // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VB_SoldierDetails;                                 // 0x02D8(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class UClass*>                         DamageTypes;                                       // 0x02E0(0x0010)(Edit, BlueprintVisible)
	class AActor*                                 ActorRef;                                          // 0x02F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             ApplyDamageToSelected;                             // 0x02F8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             DestroySelectedActor;                              // 0x0308(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             PossessSelected;                                   // 0x0318(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class USQVehicleComponent*>            VehicleComponents;                                 // 0x0328(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)

public:
	void ApplyDamageToSelected__DelegateSignature(class AActor* Param_ActorRef, class USQVehicleComponent* Component, float Amount, class UClass* Type);
	void DestroySelectedActor__DelegateSignature(class AActor* Actor);
	void PossessSelected__DelegateSignature(class ASQSoldier* Soldier);
	void ExecuteUbergraph_W_ActorDetails(int32 EntryPoint);
	void BndEvt__W_ActorDetails_Button_86_K2Node_ComponentBoundEvent_2_OnButtonClickedEvent__DelegateSignature();
	void BndEvt__W_ActorDetails_Button_Destroy_K2Node_ComponentBoundEvent_1_OnButtonClickedEvent__DelegateSignature();
	void BndEvt__W_ActorDetails_Button_Destroy_1_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	void SetSelected(class AActor* Actors);
	void SelectedVehicle(class ASQVehicle* Vehicle);
	class FText Get_Health_Value();
	ESlateVisibility ShouldShowDamageTypes();
	ESlateVisibility ShouldShowSoldierDetails();
	void SelectedDeployable(class ASQDeployable* Deployable);
	ESlateVisibility Get_VB_Damage_Visibility_0();
	class FText GetTeam();
	ESlateVisibility Get_CB_VehicleComponents_Visibility_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ActorDetails_C">();
	}
	static class UW_ActorDetails_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ActorDetails_C>();
	}
};
static_assert(alignof(UW_ActorDetails_C) == 0x000008, "Wrong alignment on UW_ActorDetails_C");
static_assert(sizeof(UW_ActorDetails_C) == 0x000338, "Wrong size on UW_ActorDetails_C");
static_assert(offsetof(UW_ActorDetails_C, UberGraphFrame) == 0x000260, "Member 'UW_ActorDetails_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, BackgroundButton) == 0x000268, "Member 'UW_ActorDetails_C::BackgroundButton' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, BTN_Possess) == 0x000270, "Member 'UW_ActorDetails_C::BTN_Possess' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, Button_Damage) == 0x000278, "Member 'UW_ActorDetails_C::Button_Damage' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, Button_Heal) == 0x000280, "Member 'UW_ActorDetails_C::Button_Heal' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, ButtonDestroy) == 0x000288, "Member 'UW_ActorDetails_C::ButtonDestroy' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, CB_DamageTypes) == 0x000290, "Member 'UW_ActorDetails_C::CB_DamageTypes' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, CB_VehicleComponents) == 0x000298, "Member 'UW_ActorDetails_C::CB_VehicleComponents' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, DamageAmountBox) == 0x0002A0, "Member 'UW_ActorDetails_C::DamageAmountBox' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, HorizontalBox) == 0x0002A8, "Member 'UW_ActorDetails_C::HorizontalBox' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, HorizontalBox_5) == 0x0002B0, "Member 'UW_ActorDetails_C::HorizontalBox_5' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, TB_Health_Value) == 0x0002B8, "Member 'UW_ActorDetails_C::TB_Health_Value' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, TB_ObjectName) == 0x0002C0, "Member 'UW_ActorDetails_C::TB_ObjectName' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, TB_Team_Value) == 0x0002C8, "Member 'UW_ActorDetails_C::TB_Team_Value' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, VB_Damage) == 0x0002D0, "Member 'UW_ActorDetails_C::VB_Damage' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, VB_SoldierDetails) == 0x0002D8, "Member 'UW_ActorDetails_C::VB_SoldierDetails' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, DamageTypes) == 0x0002E0, "Member 'UW_ActorDetails_C::DamageTypes' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, ActorRef) == 0x0002F0, "Member 'UW_ActorDetails_C::ActorRef' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, ApplyDamageToSelected) == 0x0002F8, "Member 'UW_ActorDetails_C::ApplyDamageToSelected' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, DestroySelectedActor) == 0x000308, "Member 'UW_ActorDetails_C::DestroySelectedActor' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, PossessSelected) == 0x000318, "Member 'UW_ActorDetails_C::PossessSelected' has a wrong offset!");
static_assert(offsetof(UW_ActorDetails_C, VehicleComponents) == 0x000328, "Member 'UW_ActorDetails_C::VehicleComponents' has a wrong offset!");

}

