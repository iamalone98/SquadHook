#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Menu_DeployableCategories

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialMenuModel_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Menu_DeployableCategories.BP_Menu_DeployableCategories_C
// 0x0018 (0x0070 - 0x0058)
class UBP_Menu_DeployableCategories_C final : public UBP_RadialMenuModel_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_Menu_DeployableCategories_C;     // 0x0058(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBPRadialPopulatorGotoDeployableGroup_C* Radial_Child_Populator;                            // 0x0060(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Radial_Child_Populator_Class;                      // 0x0068(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_Menu_DeployableCategories(int32 EntryPoint);
	void CreateChildWidgets(class UBaseRadialMenu_C* BaseRadialMenu);
	void CreateCenter(class UBaseRadialMenu_C* Base_Radial_Menu);
	void InstantiateChildPopulator();
	void GenerateChildDeployableGroups(class UBaseRadialMenu_C* Base_Radial_Menu, int32* Out_Widget_Count, ESQRadialWidgetSizeEnum* Out_Widget_Size);
	void CreateBackButton(class UBaseRadialMenu_C* Base_Radial_Menu, int32 In_Widget_Count, ESQRadialWidgetSizeEnum In_Widget_Size);
	void CollectDeployableGroups(class UBaseRadialMenu_C* Base_Radial_Menu, bool* Success, TArray<struct FSQDeployableGroupingStrategy>* Out_Groups);
	void DetermineWidgetSize(TArray<struct FSQDeployableGroupingStrategy>& In_Groups, ESQRadialWidgetSizeEnum* Out_Size);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Menu_DeployableCategories_C">();
	}
	static class UBP_Menu_DeployableCategories_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_Menu_DeployableCategories_C>();
	}
};
static_assert(alignof(UBP_Menu_DeployableCategories_C) == 0x000008, "Wrong alignment on UBP_Menu_DeployableCategories_C");
static_assert(sizeof(UBP_Menu_DeployableCategories_C) == 0x000070, "Wrong size on UBP_Menu_DeployableCategories_C");
static_assert(offsetof(UBP_Menu_DeployableCategories_C, UberGraphFrame_BP_Menu_DeployableCategories_C) == 0x000058, "Member 'UBP_Menu_DeployableCategories_C::UberGraphFrame_BP_Menu_DeployableCategories_C' has a wrong offset!");
static_assert(offsetof(UBP_Menu_DeployableCategories_C, Radial_Child_Populator) == 0x000060, "Member 'UBP_Menu_DeployableCategories_C::Radial_Child_Populator' has a wrong offset!");
static_assert(offsetof(UBP_Menu_DeployableCategories_C, Radial_Child_Populator_Class) == 0x000068, "Member 'UBP_Menu_DeployableCategories_C::Radial_Child_Populator_Class' has a wrong offset!");

}

