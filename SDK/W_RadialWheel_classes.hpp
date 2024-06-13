#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RadialWheel

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_RadialWheel.W_RadialWheel_C
// 0x0098 (0x0350 - 0x02B8)
class UW_RadialWheel_C final : public USQWidget_RadialWheel
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02B8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Fade;                                              // 0x02C0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UNamedSlot*                             CenterSlot;                                        // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                CursorRing;                                        // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         CurrentHoveredIndex_0;                             // 0x02D8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3F33[0x4];                                     // 0x02DC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQRadialButton*                        Center_Widget;                                     // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UW_RadialEntry_C*>               RadialEntries;                                     // 0x02E8(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	bool                                          Inactive;                                          // 0x02F8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F34[0x3];                                     // 0x02F9(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   CloseMenuActionName;                               // 0x02FC(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Radial_Centre_Hover_Division;                      // 0x0304(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Hovering_Centre;                                   // 0x0308(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F35[0x7];                                     // 0x0309(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             CenterHoverChanged;                                // 0x0310(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          Is_Open;                                           // 0x0320(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3F36[0x7];                                     // 0x0321(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 RadialMenuModel;                                   // 0x0328(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                Context;                                           // 0x0330(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              LastMousePos;                                      // 0x0338(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UClass*>                         LastOpenedMenu;                                    // 0x0340(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void CenterHoverChanged__DelegateSignature(bool bCenterHovered);
	void ExecuteUbergraph_W_RadialWheel(int32 EntryPoint);
	void Reset();
	void Radial_Option_Released(int32 Param_Index);
	void PreConstruct(bool IsDesignTime);
	void FadeAnimation(bool bReverse);
	void AddChildWidget(class UW_RadialEntry_C* RadialEntry);
	void RemoveChildWidget(const class UW_RadialEntry_C*& Item);
	struct FEventReply OnKeyUp(const struct FGeometry& MyGeometry, const struct FKeyEvent& InKeyEvent);
	void CloseSelf();
	void IsMouseInCenterHitbox(bool* CenterHitbox);
	void ClearMenu();
	void CreateMenuFromModel();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_RadialWheel_C">();
	}
	static class UW_RadialWheel_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_RadialWheel_C>();
	}
};
static_assert(alignof(UW_RadialWheel_C) == 0x000008, "Wrong alignment on UW_RadialWheel_C");
static_assert(sizeof(UW_RadialWheel_C) == 0x000350, "Wrong size on UW_RadialWheel_C");
static_assert(offsetof(UW_RadialWheel_C, UberGraphFrame) == 0x0002B8, "Member 'UW_RadialWheel_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Fade) == 0x0002C0, "Member 'UW_RadialWheel_C::Fade' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, CenterSlot) == 0x0002C8, "Member 'UW_RadialWheel_C::CenterSlot' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, CursorRing) == 0x0002D0, "Member 'UW_RadialWheel_C::CursorRing' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, CurrentHoveredIndex_0) == 0x0002D8, "Member 'UW_RadialWheel_C::CurrentHoveredIndex_0' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Center_Widget) == 0x0002E0, "Member 'UW_RadialWheel_C::Center_Widget' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, RadialEntries) == 0x0002E8, "Member 'UW_RadialWheel_C::RadialEntries' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Inactive) == 0x0002F8, "Member 'UW_RadialWheel_C::Inactive' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, CloseMenuActionName) == 0x0002FC, "Member 'UW_RadialWheel_C::CloseMenuActionName' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Radial_Centre_Hover_Division) == 0x000304, "Member 'UW_RadialWheel_C::Radial_Centre_Hover_Division' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Hovering_Centre) == 0x000308, "Member 'UW_RadialWheel_C::Hovering_Centre' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, CenterHoverChanged) == 0x000310, "Member 'UW_RadialWheel_C::CenterHoverChanged' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Is_Open) == 0x000320, "Member 'UW_RadialWheel_C::Is_Open' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, RadialMenuModel) == 0x000328, "Member 'UW_RadialWheel_C::RadialMenuModel' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, Context) == 0x000330, "Member 'UW_RadialWheel_C::Context' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, LastMousePos) == 0x000338, "Member 'UW_RadialWheel_C::LastMousePos' has a wrong offset!");
static_assert(offsetof(UW_RadialWheel_C, LastOpenedMenu) == 0x000340, "Member 'UW_RadialWheel_C::LastOpenedMenu' has a wrong offset!");

}
