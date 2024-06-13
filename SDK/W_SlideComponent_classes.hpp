#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SlideComponent

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "SlateCore_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_SlideComponent.W_SlideComponent_C
// 0x00A0 (0x0300 - 0x0260)
class UW_SlideComponent_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Border_0;                                          // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBackgroundBlur*                        ContentBG;                                         // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon;                                              // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UButton*                                SlideButton;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Name;                                           // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ABP_PlayerController_C*                 PC;                                                // 0x0290(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Widget_Class;                                      // 0x0298(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Open;                                              // 0x02A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_444A[0x7];                                     // 0x02A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UUserWidget*                            Child_Widget;                                      // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Thumbnail;                                         // 0x02B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          RotateThumbnail;                                   // 0x02B8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_444B[0x7];                                     // 0x02B9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Slide_Opened;                                      // 0x02C0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             Slide_Closed;                                      // 0x02D0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class FText                                   Name_W_SlideComponent_C;                           // 0x02E0(0x0018)(Edit, BlueprintVisible)
	EVerticalAlignment                            Button_Alignment;                                  // 0x02F8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Start_Open;                                        // 0x02F9(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)

public:
	void Slide_Opened__DelegateSignature();
	void Slide_Closed__DelegateSignature();
	void ExecuteUbergraph_W_SlideComponent(int32 EntryPoint);
	void Toggle();
	void BndEvt__SlideButton_K2Node_ComponentBoundEvent_101_OnButtonClickedEvent__DelegateSignature();
	void PreConstruct(bool IsDesignTime);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_SlideComponent_C">();
	}
	static class UW_SlideComponent_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_SlideComponent_C>();
	}
};
static_assert(alignof(UW_SlideComponent_C) == 0x000008, "Wrong alignment on UW_SlideComponent_C");
static_assert(sizeof(UW_SlideComponent_C) == 0x000300, "Wrong size on UW_SlideComponent_C");
static_assert(offsetof(UW_SlideComponent_C, UberGraphFrame) == 0x000260, "Member 'UW_SlideComponent_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Border_0) == 0x000268, "Member 'UW_SlideComponent_C::Border_0' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, ContentBG) == 0x000270, "Member 'UW_SlideComponent_C::ContentBG' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Icon) == 0x000278, "Member 'UW_SlideComponent_C::Icon' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, SlideButton) == 0x000280, "Member 'UW_SlideComponent_C::SlideButton' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, TB_Name) == 0x000288, "Member 'UW_SlideComponent_C::TB_Name' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, PC) == 0x000290, "Member 'UW_SlideComponent_C::PC' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Widget_Class) == 0x000298, "Member 'UW_SlideComponent_C::Widget_Class' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Open) == 0x0002A0, "Member 'UW_SlideComponent_C::Open' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Child_Widget) == 0x0002A8, "Member 'UW_SlideComponent_C::Child_Widget' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Thumbnail) == 0x0002B0, "Member 'UW_SlideComponent_C::Thumbnail' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, RotateThumbnail) == 0x0002B8, "Member 'UW_SlideComponent_C::RotateThumbnail' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Slide_Opened) == 0x0002C0, "Member 'UW_SlideComponent_C::Slide_Opened' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Slide_Closed) == 0x0002D0, "Member 'UW_SlideComponent_C::Slide_Closed' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Name_W_SlideComponent_C) == 0x0002E0, "Member 'UW_SlideComponent_C::Name_W_SlideComponent_C' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Button_Alignment) == 0x0002F8, "Member 'UW_SlideComponent_C::Button_Alignment' has a wrong offset!");
static_assert(offsetof(UW_SlideComponent_C, Start_Open) == 0x0002F9, "Member 'UW_SlideComponent_C::Start_Open' has a wrong offset!");

}

