#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialCenter_Deployable

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_classes.hpp"
#include "ESQCurrency_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass RadialCenter_Deployable.RadialCenter_Deployable_C
// 0x0100 (0x0430 - 0x0330)
class URadialCenter_Deployable_C final : public USQRadialButton
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0330(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UTextBlock*                             Cost;                                              // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           CostZone;                                          // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CurrencyBG;                                        // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CurrencyIcon;                                      // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             DeployableName;                                    // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Details;                                           // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              DetailsZone;                                       // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             ErrorMessage;                                      // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           ErrorZone;                                         // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      OwnerRadialMenu;                                   // 0x0380(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  RelatedActionModel;                                // 0x0388(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FSlateColor                            UnavailableCurrency;                               // 0x0390(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            UnavailableBG;                                     // 0x03B8(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            AvailableBG;                                       // 0x03E0(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            AvailableCurrency;                                 // 0x0408(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_RadialCenter_Deployable(int32 EntryPoint);
	void OnHoverWidgetChanged(class USQRadialButton* In_Hovered);
	void OnHoverBegin();
	void UpdateContent(class USQRadialButton* In_Hovered_Widget);
	void ShowDetails(class URadialItem_Deployable_C* In_Deployable_Item_Model);
	void HideDetails();
	void RefreshDeployableState(class URadialItem_Deployable_C* In_Radial_Deployable_Item, struct FSQAvailabilityState_Deployable* Out_Deployable_Availability_State);
	void ShowCost(class UBP_SQRestriction_Cost_C* InCost, bool InAvailable);
	void ShowProblem(const struct FSQAvailabilityState& In_Status, class UBP_SQAvailability_Deployable_C* In_Availability);
	void ShowRequirement(class UBP_SQAvailability_Deployable_C* In_Availability);
	void GetDeployableInfos(class URadialItem_Deployable_C* In_Radial_Deployable_Item, struct FSQAvailabilityState* Out_State, class UBP_SQAvailability_Deployable_C** Out_Availability, class UBP_SQDeployableSettings_C** Out_Settings);
	void ShowLabel(class USQRadialButton* Item);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"RadialCenter_Deployable_C">();
	}
	static class URadialCenter_Deployable_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<URadialCenter_Deployable_C>();
	}
};
static_assert(alignof(URadialCenter_Deployable_C) == 0x000008, "Wrong alignment on URadialCenter_Deployable_C");
static_assert(sizeof(URadialCenter_Deployable_C) == 0x000430, "Wrong size on URadialCenter_Deployable_C");
static_assert(offsetof(URadialCenter_Deployable_C, UberGraphFrame) == 0x000330, "Member 'URadialCenter_Deployable_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, Cost) == 0x000338, "Member 'URadialCenter_Deployable_C::Cost' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, CostZone) == 0x000340, "Member 'URadialCenter_Deployable_C::CostZone' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, CurrencyBG) == 0x000348, "Member 'URadialCenter_Deployable_C::CurrencyBG' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, CurrencyIcon) == 0x000350, "Member 'URadialCenter_Deployable_C::CurrencyIcon' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, DeployableName) == 0x000358, "Member 'URadialCenter_Deployable_C::DeployableName' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, Details) == 0x000360, "Member 'URadialCenter_Deployable_C::Details' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, DetailsZone) == 0x000368, "Member 'URadialCenter_Deployable_C::DetailsZone' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, ErrorMessage) == 0x000370, "Member 'URadialCenter_Deployable_C::ErrorMessage' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, ErrorZone) == 0x000378, "Member 'URadialCenter_Deployable_C::ErrorZone' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, OwnerRadialMenu) == 0x000380, "Member 'URadialCenter_Deployable_C::OwnerRadialMenu' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, RelatedActionModel) == 0x000388, "Member 'URadialCenter_Deployable_C::RelatedActionModel' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, UnavailableCurrency) == 0x000390, "Member 'URadialCenter_Deployable_C::UnavailableCurrency' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, UnavailableBG) == 0x0003B8, "Member 'URadialCenter_Deployable_C::UnavailableBG' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, AvailableBG) == 0x0003E0, "Member 'URadialCenter_Deployable_C::AvailableBG' has a wrong offset!");
static_assert(offsetof(URadialCenter_Deployable_C, AvailableCurrency) == 0x000408, "Member 'URadialCenter_Deployable_C::AvailableCurrency' has a wrong offset!");

}

