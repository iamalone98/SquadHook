#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ModList

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ModList.W_ModList_C
// 0x0050 (0x02B0 - 0x0260)
class UW_ModList_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                HoverCheckArea;                                    // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                MainBorder;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           ModList;                                           // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Whitelist;                                      // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_ModTooltipItem_C*                    W_ModTooltipItem_C_6;                              // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_ModTooltipItem_C*                    W_ModTooltipItem_C_7;                              // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_ModTooltipItem_C*                    W_ModTooltipItem_C_8;                              // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USQServerListItemWidget*                ServerListItem;                                    // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQSessionInfo*                         SessionInfo;                                       // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_ModList(int32 EntryPoint);
	void Init(class USQSessionInfo* Param_SessionInfo);
	void Display_Mods();
	class FText Get_TB_Whitelist_Text_0();
	void Is_Whitelisted(bool* Param_Is_Whitelisted);
	bool Is_Modded();
	void HideMods();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ModList_C">();
	}
	static class UW_ModList_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ModList_C>();
	}
};
static_assert(alignof(UW_ModList_C) == 0x000008, "Wrong alignment on UW_ModList_C");
static_assert(sizeof(UW_ModList_C) == 0x0002B0, "Wrong size on UW_ModList_C");
static_assert(offsetof(UW_ModList_C, UberGraphFrame) == 0x000260, "Member 'UW_ModList_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, HoverCheckArea) == 0x000268, "Member 'UW_ModList_C::HoverCheckArea' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, MainBorder) == 0x000270, "Member 'UW_ModList_C::MainBorder' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, ModList) == 0x000278, "Member 'UW_ModList_C::ModList' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, TB_Whitelist) == 0x000280, "Member 'UW_ModList_C::TB_Whitelist' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, W_ModTooltipItem_C_6) == 0x000288, "Member 'UW_ModList_C::W_ModTooltipItem_C_6' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, W_ModTooltipItem_C_7) == 0x000290, "Member 'UW_ModList_C::W_ModTooltipItem_C_7' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, W_ModTooltipItem_C_8) == 0x000298, "Member 'UW_ModList_C::W_ModTooltipItem_C_8' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, ServerListItem) == 0x0002A0, "Member 'UW_ModList_C::ServerListItem' has a wrong offset!");
static_assert(offsetof(UW_ModList_C, SessionInfo) == 0x0002A8, "Member 'UW_ModList_C::SessionInfo' has a wrong offset!");

}
