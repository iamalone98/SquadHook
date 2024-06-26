#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Helicopter

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "Engine_structs.hpp"
#include "W_InteractableWidgetList_Master_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_InteractableList_Helicopter.W_InteractableList_Helicopter_C
// 0x00B8 (0x0398 - 0x02E0)
class UW_InteractableList_Helicopter_C final : public UW_InteractableWidgetList_Master_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_InteractableList_Helicopter_C;    // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Fade;                                              // 0x02E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UBorder*                                Border_4;                                          // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        CommandSwitch;                                     // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IconSquad;                                         // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        IconSwitch;                                        // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_2;                                           // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           InteractList;                                      // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             ObjectName;                                        // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeClaim;                                         // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                SquadColorBorder;                                  // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_SquadID;                                        // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UClass*                                 Interact_Item_Class;                               // 0x0340(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           Fade_Timer_0;                                      // 0x0348(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          Opening_0;                                         // 0x0350(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4123[0x7];                                     // 0x0351(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FSQUsableData                          Repair_Data;                                       // 0x0358(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_W_InteractableList_Helicopter(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Create_Interaction_Items(bool Force);
	void Update_Vehicle_Claim();
	void Check_for_Repair_Kit(bool* bSuccess);
	void Get_Interact_List(class UVerticalBox** Param_InteractList);
	void Get_Fade_Animation(class UWidgetAnimation** Fade_Animation);
	void Get_Original_Offset();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_InteractableList_Helicopter_C">();
	}
	static class UW_InteractableList_Helicopter_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_InteractableList_Helicopter_C>();
	}
};
static_assert(alignof(UW_InteractableList_Helicopter_C) == 0x000008, "Wrong alignment on UW_InteractableList_Helicopter_C");
static_assert(sizeof(UW_InteractableList_Helicopter_C) == 0x000398, "Wrong size on UW_InteractableList_Helicopter_C");
static_assert(offsetof(UW_InteractableList_Helicopter_C, UberGraphFrame_W_InteractableList_Helicopter_C) == 0x0002E0, "Member 'UW_InteractableList_Helicopter_C::UberGraphFrame_W_InteractableList_Helicopter_C' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Fade) == 0x0002E8, "Member 'UW_InteractableList_Helicopter_C::Fade' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Border_4) == 0x0002F0, "Member 'UW_InteractableList_Helicopter_C::Border_4' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, CommandSwitch) == 0x0002F8, "Member 'UW_InteractableList_Helicopter_C::CommandSwitch' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, IconSquad) == 0x000300, "Member 'UW_InteractableList_Helicopter_C::IconSquad' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, IconSwitch) == 0x000308, "Member 'UW_InteractableList_Helicopter_C::IconSwitch' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Image_2) == 0x000310, "Member 'UW_InteractableList_Helicopter_C::Image_2' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, InteractList) == 0x000318, "Member 'UW_InteractableList_Helicopter_C::InteractList' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, ObjectName) == 0x000320, "Member 'UW_InteractableList_Helicopter_C::ObjectName' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, SizeClaim) == 0x000328, "Member 'UW_InteractableList_Helicopter_C::SizeClaim' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, SquadColorBorder) == 0x000330, "Member 'UW_InteractableList_Helicopter_C::SquadColorBorder' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, TB_SquadID) == 0x000338, "Member 'UW_InteractableList_Helicopter_C::TB_SquadID' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Interact_Item_Class) == 0x000340, "Member 'UW_InteractableList_Helicopter_C::Interact_Item_Class' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Fade_Timer_0) == 0x000348, "Member 'UW_InteractableList_Helicopter_C::Fade_Timer_0' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Opening_0) == 0x000350, "Member 'UW_InteractableList_Helicopter_C::Opening_0' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Helicopter_C, Repair_Data) == 0x000358, "Member 'UW_InteractableList_Helicopter_C::Repair_Data' has a wrong offset!");

}

