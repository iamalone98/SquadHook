#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SquadList

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_SquadList.W_SquadList_C
// 0x0058 (0x02B8 - 0x0260)
class UW_SquadList_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UVerticalBox*                           CommanderVoteContainer;                            // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UGridPanel*                             Grid_Squads;                                       // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox_List;                                    // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_SquadCreate_C*                       SquadCreate;                                       // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_CommandVoteParent_C*                 W_CommandVoteParent;                               // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_UnassignedList_C*                    W_Unassigned;                                      // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class UW_SquadListItem_C*>             SquadListItems;                                    // 0x02A0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	bool                                          Show_CMD_Voting;                                   // 0x02B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_W_SquadList(int32 EntryPoint);
	void Get_Commander_Active_for_Squad_List();
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_SquadList_C">();
	}
	static class UW_SquadList_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_SquadList_C>();
	}
};
static_assert(alignof(UW_SquadList_C) == 0x000008, "Wrong alignment on UW_SquadList_C");
static_assert(sizeof(UW_SquadList_C) == 0x0002B8, "Wrong size on UW_SquadList_C");
static_assert(offsetof(UW_SquadList_C, UberGraphFrame) == 0x000260, "Member 'UW_SquadList_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, CommanderVoteContainer) == 0x000268, "Member 'UW_SquadList_C::CommanderVoteContainer' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, Grid_Squads) == 0x000270, "Member 'UW_SquadList_C::Grid_Squads' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, Image_1) == 0x000278, "Member 'UW_SquadList_C::Image_1' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, ScrollBox_List) == 0x000280, "Member 'UW_SquadList_C::ScrollBox_List' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, SquadCreate) == 0x000288, "Member 'UW_SquadList_C::SquadCreate' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, W_CommandVoteParent) == 0x000290, "Member 'UW_SquadList_C::W_CommandVoteParent' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, W_Unassigned) == 0x000298, "Member 'UW_SquadList_C::W_Unassigned' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, SquadListItems) == 0x0002A0, "Member 'UW_SquadList_C::SquadListItems' has a wrong offset!");
static_assert(offsetof(UW_SquadList_C, Show_CMD_Voting) == 0x0002B0, "Member 'UW_SquadList_C::Show_CMD_Voting' has a wrong offset!");

}
