#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: CreditsWindow

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass CreditsWindow.CreditsWindow_C
// 0x0030 (0x0290 - 0x0260)
class UCreditsWindow_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UVerticalBox*                           CreditList;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScrollBox*                             CreditsScrollBox;                                  // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_78;                                          // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_288;                                         // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	bool                                          bIsHovered;                                        // 0x0288(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_35A1[0x3];                                     // 0x0289(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         ScrollSpeed;                                       // 0x028C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_CreditsWindow(int32 EntryPoint);
	void OnMouseEnter(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void OnMouseLeave(const struct FPointerEvent& MouseEvent);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void LoadCredits();
	void CheckScrollToTop(class UScrollBox* ScrollBox, float NewScrollOffset);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"CreditsWindow_C">();
	}
	static class UCreditsWindow_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UCreditsWindow_C>();
	}
};
static_assert(alignof(UCreditsWindow_C) == 0x000008, "Wrong alignment on UCreditsWindow_C");
static_assert(sizeof(UCreditsWindow_C) == 0x000290, "Wrong size on UCreditsWindow_C");
static_assert(offsetof(UCreditsWindow_C, UberGraphFrame) == 0x000260, "Member 'UCreditsWindow_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, CreditList) == 0x000268, "Member 'UCreditsWindow_C::CreditList' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, CreditsScrollBox) == 0x000270, "Member 'UCreditsWindow_C::CreditsScrollBox' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, Image_78) == 0x000278, "Member 'UCreditsWindow_C::Image_78' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, Image_288) == 0x000280, "Member 'UCreditsWindow_C::Image_288' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, bIsHovered) == 0x000288, "Member 'UCreditsWindow_C::bIsHovered' has a wrong offset!");
static_assert(offsetof(UCreditsWindow_C, ScrollSpeed) == 0x00028C, "Member 'UCreditsWindow_C::ScrollSpeed' has a wrong offset!");

}

