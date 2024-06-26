#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_SightRange

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_SightRange.UMG_SightRange_C
// 0x0028 (0x0290 - 0x0268)
class UUMG_SightRange_C final : public USQUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0268(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Fade;                                              // 0x0270(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Background;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_0;                                          // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             RangeText;                                         // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_SightRange(int32 EntryPoint);
	void UpdateState();
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_SightRange_C">();
	}
	static class UUMG_SightRange_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_SightRange_C>();
	}
};
static_assert(alignof(UUMG_SightRange_C) == 0x000008, "Wrong alignment on UUMG_SightRange_C");
static_assert(sizeof(UUMG_SightRange_C) == 0x000290, "Wrong size on UUMG_SightRange_C");
static_assert(offsetof(UUMG_SightRange_C, UberGraphFrame) == 0x000268, "Member 'UUMG_SightRange_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_SightRange_C, Fade) == 0x000270, "Member 'UUMG_SightRange_C::Fade' has a wrong offset!");
static_assert(offsetof(UUMG_SightRange_C, Background) == 0x000278, "Member 'UUMG_SightRange_C::Background' has a wrong offset!");
static_assert(offsetof(UUMG_SightRange_C, Border_0) == 0x000280, "Member 'UUMG_SightRange_C::Border_0' has a wrong offset!");
static_assert(offsetof(UUMG_SightRange_C, RangeText) == 0x000288, "Member 'UUMG_SightRange_C::RangeText' has a wrong offset!");

}

