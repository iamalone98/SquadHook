#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_ApprovalQueueWidget

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_ApprovalQueueWidget.UMG_ApprovalQueueWidget_C
// 0x0048 (0x0320 - 0x02D8)
class UUMG_ApprovalQueueWidget_C final : public USQApprovalQueueWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02D8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Out;                                               // 0x02E0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       In;                                                // 0x02E8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Approve;                                           // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BlackBG;                                           // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Disapprove;                                        // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             ScrollBox_4;                                       // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_72;                                      // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_73;                                      // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_ApprovalQueueWidget(int32 EntryPoint);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_ApprovalQueueWidget_C">();
	}
	static class UUMG_ApprovalQueueWidget_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_ApprovalQueueWidget_C>();
	}
};
static_assert(alignof(UUMG_ApprovalQueueWidget_C) == 0x000008, "Wrong alignment on UUMG_ApprovalQueueWidget_C");
static_assert(sizeof(UUMG_ApprovalQueueWidget_C) == 0x000320, "Wrong size on UUMG_ApprovalQueueWidget_C");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, UberGraphFrame) == 0x0002D8, "Member 'UUMG_ApprovalQueueWidget_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, Out) == 0x0002E0, "Member 'UUMG_ApprovalQueueWidget_C::Out' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, In) == 0x0002E8, "Member 'UUMG_ApprovalQueueWidget_C::In' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, Approve) == 0x0002F0, "Member 'UUMG_ApprovalQueueWidget_C::Approve' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, BlackBG) == 0x0002F8, "Member 'UUMG_ApprovalQueueWidget_C::BlackBG' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, Disapprove) == 0x000300, "Member 'UUMG_ApprovalQueueWidget_C::Disapprove' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, ScrollBox_4) == 0x000308, "Member 'UUMG_ApprovalQueueWidget_C::ScrollBox_4' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, TextBlock_72) == 0x000310, "Member 'UUMG_ApprovalQueueWidget_C::TextBlock_72' has a wrong offset!");
static_assert(offsetof(UUMG_ApprovalQueueWidget_C, TextBlock_73) == 0x000318, "Member 'UUMG_ApprovalQueueWidget_C::TextBlock_73' has a wrong offset!");

}
