#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_PopupGeneric

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_PopupGeneric.W_PopupGeneric_C
// 0x0080 (0x02E0 - 0x0260)
class UW_PopupGeneric_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                Button_Close;                                      // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         DragArea;                                          // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           GenericWidgetCanvas;                               // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                HoverCheckArea;                                    // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	bool                                          Was_hovered;                                       // 0x0290(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46EC[0x7];                                     // 0x0291(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 Popup_Widget_Class;                                // 0x0298(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	bool                                          Ignore_Hover;                                      // 0x02A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          Can_Drag;                                          // 0x02A1(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          Dragging;                                          // 0x02A2(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46ED[0x1];                                     // 0x02A3(0x0001)(Fixing Size After Last Property [ Dumper-7 ])
	struct FVector2D                              Drag_Offset;                                       // 0x02A4(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              Widget_Screen_Pos;                                 // 0x02AC(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_46EE[0x4];                                     // 0x02B4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Removed;                                           // 0x02B8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	struct FVector2D                              Alignment;                                         // 0x02C8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Offset_Size;                                       // 0x02D0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_46EF[0x4];                                     // 0x02D4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUserWidget*                            Spawned_Widget;                                    // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void Removed__DelegateSignature();
	void ExecuteUbergraph_W_PopupGeneric(int32 EntryPoint);
	void Clear();
	void Destruct();
	void Reset();
	void BndEvt__Button_Close_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	void OnDragCancelled(const struct FPointerEvent& PointerEvent, class UDragDropOperation* Operation);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	void PreConstruct(bool IsDesignTime);
	struct FEventReply OnMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void OnDragDetected(const struct FGeometry& MyGeometry, const struct FPointerEvent& PointerEvent, class UDragDropOperation** Operation);
	void Setup_Dragging(bool Param_Can_Drag);
	struct FEventReply OnMouseButtonUp(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_PopupGeneric_C">();
	}
	static class UW_PopupGeneric_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_PopupGeneric_C>();
	}
};
static_assert(alignof(UW_PopupGeneric_C) == 0x000008, "Wrong alignment on UW_PopupGeneric_C");
static_assert(sizeof(UW_PopupGeneric_C) == 0x0002E0, "Wrong size on UW_PopupGeneric_C");
static_assert(offsetof(UW_PopupGeneric_C, UberGraphFrame) == 0x000260, "Member 'UW_PopupGeneric_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Button_Close) == 0x000268, "Member 'UW_PopupGeneric_C::Button_Close' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, DragArea) == 0x000270, "Member 'UW_PopupGeneric_C::DragArea' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, GenericWidgetCanvas) == 0x000278, "Member 'UW_PopupGeneric_C::GenericWidgetCanvas' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, HoverCheckArea) == 0x000280, "Member 'UW_PopupGeneric_C::HoverCheckArea' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Image_0) == 0x000288, "Member 'UW_PopupGeneric_C::Image_0' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Was_hovered) == 0x000290, "Member 'UW_PopupGeneric_C::Was_hovered' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Popup_Widget_Class) == 0x000298, "Member 'UW_PopupGeneric_C::Popup_Widget_Class' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Ignore_Hover) == 0x0002A0, "Member 'UW_PopupGeneric_C::Ignore_Hover' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Can_Drag) == 0x0002A1, "Member 'UW_PopupGeneric_C::Can_Drag' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Dragging) == 0x0002A2, "Member 'UW_PopupGeneric_C::Dragging' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Drag_Offset) == 0x0002A4, "Member 'UW_PopupGeneric_C::Drag_Offset' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Widget_Screen_Pos) == 0x0002AC, "Member 'UW_PopupGeneric_C::Widget_Screen_Pos' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Removed) == 0x0002B8, "Member 'UW_PopupGeneric_C::Removed' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Alignment) == 0x0002C8, "Member 'UW_PopupGeneric_C::Alignment' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Offset_Size) == 0x0002D0, "Member 'UW_PopupGeneric_C::Offset_Size' has a wrong offset!");
static_assert(offsetof(UW_PopupGeneric_C, Spawned_Widget) == 0x0002D8, "Member 'UW_PopupGeneric_C::Spawned_Widget' has a wrong offset!");

}

