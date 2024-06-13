#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RoleQuickList

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "W_RoleList_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_RoleQuickList.W_RoleQuickList_C
// 0x0058 (0x0328 - 0x02D0)
class UW_RoleQuickList_C final : public UW_RoleList_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_W_RoleQuickList_C;                  // 0x02D0(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                UnavailabilityHeader;                              // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VerticalBox_RoleGroups;                            // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class UImage*>                         SeparatorList;                                     // 0x02E8(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	FMulticastInlineDelegateProperty_             OnMouseEntered;                                    // 0x02F8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnMouseLeft;                                       // 0x0308(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          bMouseEntered;                                     // 0x0318(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bSubrolesOpen;                                     // 0x0319(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_47E9[0x6];                                     // 0x031A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           MouseLeaveTimerHandle;                             // 0x0320(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void OnMouseEntered__DelegateSignature();
	void OnMouseLeft__DelegateSignature();
	void ExecuteUbergraph_W_RoleQuickList(int32 EntryPoint);
	void OnTimerMouseLeave();
	void OnMouseLeave(const struct FPointerEvent& MouseEvent);
	void OnMouseEnter(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void OnTick(const TArray<struct FSQAvailabilityState_Role>& In_Player_Role_States);
	void ClearGroups();
	void CreateGroupWidgets(TArray<class UW_RoleGroup_C*>* Out_RoleGroup, bool* Out_Success);
	void AddSeparator();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_RoleQuickList_C">();
	}
	static class UW_RoleQuickList_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_RoleQuickList_C>();
	}
};
static_assert(alignof(UW_RoleQuickList_C) == 0x000008, "Wrong alignment on UW_RoleQuickList_C");
static_assert(sizeof(UW_RoleQuickList_C) == 0x000328, "Wrong size on UW_RoleQuickList_C");
static_assert(offsetof(UW_RoleQuickList_C, UberGraphFrame_W_RoleQuickList_C) == 0x0002D0, "Member 'UW_RoleQuickList_C::UberGraphFrame_W_RoleQuickList_C' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, UnavailabilityHeader) == 0x0002D8, "Member 'UW_RoleQuickList_C::UnavailabilityHeader' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, VerticalBox_RoleGroups) == 0x0002E0, "Member 'UW_RoleQuickList_C::VerticalBox_RoleGroups' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, SeparatorList) == 0x0002E8, "Member 'UW_RoleQuickList_C::SeparatorList' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, OnMouseEntered) == 0x0002F8, "Member 'UW_RoleQuickList_C::OnMouseEntered' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, OnMouseLeft) == 0x000308, "Member 'UW_RoleQuickList_C::OnMouseLeft' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, bMouseEntered) == 0x000318, "Member 'UW_RoleQuickList_C::bMouseEntered' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, bSubrolesOpen) == 0x000319, "Member 'UW_RoleQuickList_C::bSubrolesOpen' has a wrong offset!");
static_assert(offsetof(UW_RoleQuickList_C, MouseLeaveTimerHandle) == 0x000320, "Member 'UW_RoleQuickList_C::MouseLeaveTimerHandle' has a wrong offset!");

}
