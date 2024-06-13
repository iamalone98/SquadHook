#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_DragDropFireteamSlot

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_DragDropFireteamSlot.W_DragDropFireteamSlot_C
// 0x0028 (0x0288 - 0x0260)
class UW_DragDropFireteamSlot_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_0;                                          // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TBName;                                            // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	int32                                         FireTeamId;                                        // 0x0278(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          LeaderSlot;                                        // 0x027C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4281[0x3];                                     // 0x027D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    My_PC;                                             // 0x0280(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_DragDropFireteamSlot(int32 EntryPoint);
	void PreConstruct(bool IsDesignTime);
	void Refresh_Text();
	void OnDragEnter(const struct FGeometry& MyGeometry, const struct FPointerEvent& PointerEvent, class UDragDropOperation* Operation);
	void OnDragLeave(const struct FPointerEvent& PointerEvent, class UDragDropOperation* Operation);
	void Construct();
	bool OnDrop(const struct FGeometry& MyGeometry, const struct FPointerEvent& PointerEvent, class UDragDropOperation* Operation);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_DragDropFireteamSlot_C">();
	}
	static class UW_DragDropFireteamSlot_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_DragDropFireteamSlot_C>();
	}
};
static_assert(alignof(UW_DragDropFireteamSlot_C) == 0x000008, "Wrong alignment on UW_DragDropFireteamSlot_C");
static_assert(sizeof(UW_DragDropFireteamSlot_C) == 0x000288, "Wrong size on UW_DragDropFireteamSlot_C");
static_assert(offsetof(UW_DragDropFireteamSlot_C, UberGraphFrame) == 0x000260, "Member 'UW_DragDropFireteamSlot_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_DragDropFireteamSlot_C, Border_0) == 0x000268, "Member 'UW_DragDropFireteamSlot_C::Border_0' has a wrong offset!");
static_assert(offsetof(UW_DragDropFireteamSlot_C, TBName) == 0x000270, "Member 'UW_DragDropFireteamSlot_C::TBName' has a wrong offset!");
static_assert(offsetof(UW_DragDropFireteamSlot_C, FireTeamId) == 0x000278, "Member 'UW_DragDropFireteamSlot_C::FireTeamId' has a wrong offset!");
static_assert(offsetof(UW_DragDropFireteamSlot_C, LeaderSlot) == 0x00027C, "Member 'UW_DragDropFireteamSlot_C::LeaderSlot' has a wrong offset!");
static_assert(offsetof(UW_DragDropFireteamSlot_C, My_PC) == 0x000280, "Member 'UW_DragDropFireteamSlot_C::My_PC' has a wrong offset!");

}
