#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InteractableList_Mines

#include "Basic.hpp"

#include "Squad_structs.hpp"
#include "Engine_structs.hpp"
#include "W_InteractableWidgetList_Master_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_InteractableList_Mines.W_InteractableList_Mines_C
// 0x0160 (0x0440 - 0x02E0)
class UW_InteractableList_Mines_C final : public UW_InteractableWidgetList_Master_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_InteractableList_Mines_C;         // 0x02E0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Fade;                                              // 0x02E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UVerticalBox*                           InteractList;                                      // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             ObjectName;                                        // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	struct FSQUsableData                          Need_Shovel_Data;                                  // 0x0300(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQUsableData                          How_to_use_Data;                                   // 0x0340(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQUsableData                          No_Shovel_Data;                                    // 0x0380(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQUsableData                          Unbuild_Only_Data;                                 // 0x03C0(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSQUsableData                          Pickup_Data;                                       // 0x0400(0x0040)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_W_InteractableList_Mines(int32 EntryPoint);
	void Set_Custom_Data();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Soldier_Has_Shovel(bool* Shovel_Equipped, bool* Owns_Shovel);
	void Is_Deployable_Built(bool* Full_Health, ESQBuildState* BuildState);
	void Create_Shovel_Items();
	void Get_Interact_List(class UVerticalBox** Param_InteractList);
	void Get_Fade_Animation(class UWidgetAnimation** Fade_Animation);
	void Soldier_Has_Mines(bool* Owns_Mines);
	void InsertPickupInteractData(TArray<struct FSQUsableWidgetData>& InteractData, ESQBuildState CurrentBuildState, int32 InsertAtIndex);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_InteractableList_Mines_C">();
	}
	static class UW_InteractableList_Mines_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_InteractableList_Mines_C>();
	}
};
static_assert(alignof(UW_InteractableList_Mines_C) == 0x000008, "Wrong alignment on UW_InteractableList_Mines_C");
static_assert(sizeof(UW_InteractableList_Mines_C) == 0x000440, "Wrong size on UW_InteractableList_Mines_C");
static_assert(offsetof(UW_InteractableList_Mines_C, UberGraphFrame_W_InteractableList_Mines_C) == 0x0002E0, "Member 'UW_InteractableList_Mines_C::UberGraphFrame_W_InteractableList_Mines_C' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, Fade) == 0x0002E8, "Member 'UW_InteractableList_Mines_C::Fade' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, InteractList) == 0x0002F0, "Member 'UW_InteractableList_Mines_C::InteractList' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, ObjectName) == 0x0002F8, "Member 'UW_InteractableList_Mines_C::ObjectName' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, Need_Shovel_Data) == 0x000300, "Member 'UW_InteractableList_Mines_C::Need_Shovel_Data' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, How_to_use_Data) == 0x000340, "Member 'UW_InteractableList_Mines_C::How_to_use_Data' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, No_Shovel_Data) == 0x000380, "Member 'UW_InteractableList_Mines_C::No_Shovel_Data' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, Unbuild_Only_Data) == 0x0003C0, "Member 'UW_InteractableList_Mines_C::Unbuild_Only_Data' has a wrong offset!");
static_assert(offsetof(UW_InteractableList_Mines_C, Pickup_Data) == 0x000400, "Member 'UW_InteractableList_Mines_C::Pickup_Data' has a wrong offset!");

}

