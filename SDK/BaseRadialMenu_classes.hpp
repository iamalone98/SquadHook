#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BaseRadialMenu

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BaseRadialMenu.BaseRadialMenu_C
// 0x0148 (0x03A8 - 0x0260)
class UBaseRadialMenu_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Fade;                                              // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UNamedSlot*                             CenterSlot;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                CursorRing;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           Panel;                                             // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RingBG;                                            // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           RingWidgetsPanel;                                  // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class USQRadialButton*>                OuterRingWidgets;                                  // 0x0298(0x0010)(Edit, BlueprintVisible, Transient, DisableEditOnInstance, ContainsInstancedReference)
	class USQRadialButton*                        Center_Widget;                                     // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, Transient, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxOuterDistance;                                  // 0x02B0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ActiveOuterRingDistance;                           // 0x02B4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         InactiveOuterRingDistance;                         // 0x02B8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_414C[0x4];                                     // 0x02BC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnOptionClicked;                                   // 0x02C0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             OnCenterClicked;                                   // 0x02D0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class FName                                   CloseMenuActionName;                               // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Inactive;                                          // 0x02E8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_414D[0x7];                                     // 0x02E9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 RadialMenuModel;                                   // 0x02F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, Transient, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UObject*                                Context;                                           // 0x02F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, Transient, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCurveFloat*                            RingScale;                                         // 0x0300(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MaxDistanceFromContext;                            // 0x0308(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RadialSize;                                        // 0x030C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             HoverWidgetChanged;                                // 0x0310(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class USoundBase*                             MouseClickSoundCue;                                // 0x0320(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Desired_Angle;                                     // 0x0328(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Mouse_Speed_Threshold;                             // 0x032C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              LastMousePos;                                      // 0x0330(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Last_Hover_Index;                                  // 0x0338(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_414E[0x4];                                     // 0x033C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Centre_Hover_Changed;                              // 0x0340(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          Hovering_Centre;                                   // 0x0350(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_414F[0x7];                                     // 0x0351(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnRadialMenuDestroyed;                             // 0x0358(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	TArray<class UBP_RadialItemModel_C*>          OuterRingModels;                                   // 0x0368(0x0010)(Edit, BlueprintVisible, Transient, DisableEditOnInstance)
	bool                                          Is_Open;                                           // 0x0378(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4150[0x3];                                     // 0x0379(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Radial_Centre_Hover_Division;                      // 0x037C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UClass*>                         LastOpenedMenu;                                    // 0x0380(0x0010)(Edit, BlueprintVisible, Transient, DisableEditOnInstance)
	bool                                          bEditMode;                                         // 0x0390(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_4151[0x7];                                     // 0x0391(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             OnSelfClosed;                                      // 0x0398(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void OnOptionClicked__DelegateSignature(int32 OptionIndex, class UBaseRadialMenu_C* Param_Context);
	void OnCenterClicked__DelegateSignature(class UBaseRadialMenu_C* Param_Context);
	void HoverWidgetChanged__DelegateSignature();
	void Centre_Hover_Changed__DelegateSignature(bool Centre_Hovered);
	void OnRadialMenuDestroyed__DelegateSignature();
	void OnSelfClosed__DelegateSignature();
	void ExecuteUbergraph_BaseRadialMenu(int32 EntryPoint);
	void ButtonRelease(class UBP_RadialItemModel_C* Item);
	void Radial_Option_Released(int32 Param_Index);
	void Reset(bool bCenterMouse);
	void ButtonPress(class UBP_RadialItemModel_C* Item);
	void Radial_Option_Clicked(int32 Param_Index);
	void Center_Button_Clicked();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void IsMouseInCenterHitbox(bool* CenterHitbox);
	void GetOuterWidgetIndex(int32* WidgetIndex);
	void Add_Center_Widget(class USQRadialButton* Entry);
	void Clear_Menu();
	void AddChild(class USQRadialButton* Entry, class UBP_RadialItemModel_C* Model);
	void LayoutOuterRing();
	struct FEventReply OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	struct FEventReply OnKeyUp(const struct FGeometry& MyGeometry, const struct FKeyEvent& InKeyEvent);
	void Notify_HoverOver();
	void GetHoverWidget(class USQRadialButton** HoverWidget);
	void SetHoveringWidget(class USQRadialButton* NewHover, class USQRadialButton* OldHover);
	void CreateMenuFromModel();
	void CloseSelf();
	void Destroy();
	void GetSelectedOuterWidget(int32* Output_Get, float* Actual_Angle);
	void CreateRadialWidget(class UClass* WidgetClass, class USQUserWidget** CreatedWidget);
	void CreateToolTip(class UBP_RadialItemModel_C* InOuterItemModel, class UUserWidget** OutToolTip);
	void Sort_Radial_Z_Order();
	void Return_to_Previous_Menu();
	struct FEventReply OnMouseButtonDoubleClick(const struct FGeometry& InMyGeometry, const struct FPointerEvent& InMouseEvent);
	void FadeAnimation(bool Reverse);
	void Finished_Closed_Animation();
	struct FEventReply OnMouseButtonUp(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void GetWidgetCenter(struct FVector2D* WidgetCenter);
	void SequenceEvent__ENTRYPOINTBaseRadialMenu_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BaseRadialMenu_C">();
	}
	static class UBaseRadialMenu_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBaseRadialMenu_C>();
	}
};
static_assert(alignof(UBaseRadialMenu_C) == 0x000008, "Wrong alignment on UBaseRadialMenu_C");
static_assert(sizeof(UBaseRadialMenu_C) == 0x0003A8, "Wrong size on UBaseRadialMenu_C");
static_assert(offsetof(UBaseRadialMenu_C, UberGraphFrame) == 0x000260, "Member 'UBaseRadialMenu_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Fade) == 0x000268, "Member 'UBaseRadialMenu_C::Fade' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, CenterSlot) == 0x000270, "Member 'UBaseRadialMenu_C::CenterSlot' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, CursorRing) == 0x000278, "Member 'UBaseRadialMenu_C::CursorRing' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Panel) == 0x000280, "Member 'UBaseRadialMenu_C::Panel' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, RingBG) == 0x000288, "Member 'UBaseRadialMenu_C::RingBG' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, RingWidgetsPanel) == 0x000290, "Member 'UBaseRadialMenu_C::RingWidgetsPanel' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OuterRingWidgets) == 0x000298, "Member 'UBaseRadialMenu_C::OuterRingWidgets' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Center_Widget) == 0x0002A8, "Member 'UBaseRadialMenu_C::Center_Widget' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, MaxOuterDistance) == 0x0002B0, "Member 'UBaseRadialMenu_C::MaxOuterDistance' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, ActiveOuterRingDistance) == 0x0002B4, "Member 'UBaseRadialMenu_C::ActiveOuterRingDistance' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, InactiveOuterRingDistance) == 0x0002B8, "Member 'UBaseRadialMenu_C::InactiveOuterRingDistance' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OnOptionClicked) == 0x0002C0, "Member 'UBaseRadialMenu_C::OnOptionClicked' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OnCenterClicked) == 0x0002D0, "Member 'UBaseRadialMenu_C::OnCenterClicked' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, CloseMenuActionName) == 0x0002E0, "Member 'UBaseRadialMenu_C::CloseMenuActionName' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Inactive) == 0x0002E8, "Member 'UBaseRadialMenu_C::Inactive' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, RadialMenuModel) == 0x0002F0, "Member 'UBaseRadialMenu_C::RadialMenuModel' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Context) == 0x0002F8, "Member 'UBaseRadialMenu_C::Context' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, RingScale) == 0x000300, "Member 'UBaseRadialMenu_C::RingScale' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, MaxDistanceFromContext) == 0x000308, "Member 'UBaseRadialMenu_C::MaxDistanceFromContext' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, RadialSize) == 0x00030C, "Member 'UBaseRadialMenu_C::RadialSize' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, HoverWidgetChanged) == 0x000310, "Member 'UBaseRadialMenu_C::HoverWidgetChanged' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, MouseClickSoundCue) == 0x000320, "Member 'UBaseRadialMenu_C::MouseClickSoundCue' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Desired_Angle) == 0x000328, "Member 'UBaseRadialMenu_C::Desired_Angle' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Mouse_Speed_Threshold) == 0x00032C, "Member 'UBaseRadialMenu_C::Mouse_Speed_Threshold' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, LastMousePos) == 0x000330, "Member 'UBaseRadialMenu_C::LastMousePos' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Last_Hover_Index) == 0x000338, "Member 'UBaseRadialMenu_C::Last_Hover_Index' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Centre_Hover_Changed) == 0x000340, "Member 'UBaseRadialMenu_C::Centre_Hover_Changed' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Hovering_Centre) == 0x000350, "Member 'UBaseRadialMenu_C::Hovering_Centre' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OnRadialMenuDestroyed) == 0x000358, "Member 'UBaseRadialMenu_C::OnRadialMenuDestroyed' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OuterRingModels) == 0x000368, "Member 'UBaseRadialMenu_C::OuterRingModels' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Is_Open) == 0x000378, "Member 'UBaseRadialMenu_C::Is_Open' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, Radial_Centre_Hover_Division) == 0x00037C, "Member 'UBaseRadialMenu_C::Radial_Centre_Hover_Division' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, LastOpenedMenu) == 0x000380, "Member 'UBaseRadialMenu_C::LastOpenedMenu' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, bEditMode) == 0x000390, "Member 'UBaseRadialMenu_C::bEditMode' has a wrong offset!");
static_assert(offsetof(UBaseRadialMenu_C, OnSelfClosed) == 0x000398, "Member 'UBaseRadialMenu_C::OnSelfClosed' has a wrong offset!");

}

