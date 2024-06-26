#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ContextMenu

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ContextMenu.W_ContextMenu_C
// 0x0048 (0x02A8 - 0x0260)
class UW_ContextMenu_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_191;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           VerticalBox_78;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             OnActionExecuted;                                  // 0x0278(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class FText>                           Entries;                                           // 0x0288(0x0010)(Edit, BlueprintVisible, ExposeOnSpawn)
	struct FTimerHandle                           TimerHandle;                                       // 0x0298(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	float                                         ClearTime;                                         // 0x02A0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void OnActionExecuted__DelegateSignature(int32 ActionIndex);
	void ExecuteUbergraph_W_ContextMenu(int32 EntryPoint);
	void OnHoveredEnd();
	void OnEntryPressed(int32 Param_Index);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	void CreateList(TArray<class FText>& Array);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ContextMenu_C">();
	}
	static class UW_ContextMenu_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ContextMenu_C>();
	}
};
static_assert(alignof(UW_ContextMenu_C) == 0x000008, "Wrong alignment on UW_ContextMenu_C");
static_assert(sizeof(UW_ContextMenu_C) == 0x0002A8, "Wrong size on UW_ContextMenu_C");
static_assert(offsetof(UW_ContextMenu_C, UberGraphFrame) == 0x000260, "Member 'UW_ContextMenu_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, Border_191) == 0x000268, "Member 'UW_ContextMenu_C::Border_191' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, VerticalBox_78) == 0x000270, "Member 'UW_ContextMenu_C::VerticalBox_78' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, OnActionExecuted) == 0x000278, "Member 'UW_ContextMenu_C::OnActionExecuted' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, Entries) == 0x000288, "Member 'UW_ContextMenu_C::Entries' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, TimerHandle) == 0x000298, "Member 'UW_ContextMenu_C::TimerHandle' has a wrong offset!");
static_assert(offsetof(UW_ContextMenu_C, ClearTime) == 0x0002A0, "Member 'UW_ContextMenu_C::ClearTime' has a wrong offset!");

}

