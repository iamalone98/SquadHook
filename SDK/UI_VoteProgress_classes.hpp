#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UI_VoteProgress

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UI_VoteProgress.UI_VoteProgress_C
// 0x0098 (0x02F8 - 0x0260)
class UUI_VoteProgress_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UUMG_VoteInfoButton_C*                  FactionInfo;                                       // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_246;                                         // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UUMG_VoteInfoButton_C*                  MapInfo;                                           // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             MapSubText;                                        // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             MapText;                                           // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Team1Subtext;                                      // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Team1Text;                                         // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Team2Subtext;                                      // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Team2Text;                                         // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TArray<class UTextBlock*>                     MainTextList;                                      // 0x02B8(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	TArray<class UTextBlock*>                     SubTextList;                                       // 0x02C8(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	FMulticastInlineDelegateProperty_             RequestMapInfo;                                    // 0x02D8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             RequestFactionInfo;                                // 0x02E8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)

public:
	void RequestMapInfo__DelegateSignature();
	void RequestFactionInfo__DelegateSignature();
	void ExecuteUbergraph_UI_VoteProgress(int32 EntryPoint);
	void BndEvt__UI_VoteProgress_FactionInfo_K2Node_ComponentBoundEvent_1_InfoClicked__DelegateSignature();
	void BndEvt__UI_VoteProgress_MapInfo_K2Node_ComponentBoundEvent_0_InfoClicked__DelegateSignature();
	void Construct();
	void UpdateTexts(TArray<class FText>& InText);
	void UpdateSubtexts(TArray<class FText>& InText);
	void MarkActive(int32 Param_Index);
	void MakeTextActive(class UTextBlock* Text, bool Active);
	void MakeTextGrayed(bool Grayed, class UTextBlock* InputPin);
	void GetSubtext(int32 Param_Index, class FText* OutSubtext);
	void ShowMapInfoButton();
	void ShowFactionInfoButton();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UI_VoteProgress_C">();
	}
	static class UUI_VoteProgress_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUI_VoteProgress_C>();
	}
};
static_assert(alignof(UUI_VoteProgress_C) == 0x000008, "Wrong alignment on UUI_VoteProgress_C");
static_assert(sizeof(UUI_VoteProgress_C) == 0x0002F8, "Wrong size on UUI_VoteProgress_C");
static_assert(offsetof(UUI_VoteProgress_C, UberGraphFrame) == 0x000260, "Member 'UUI_VoteProgress_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, FactionInfo) == 0x000268, "Member 'UUI_VoteProgress_C::FactionInfo' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Image) == 0x000270, "Member 'UUI_VoteProgress_C::Image' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Image_246) == 0x000278, "Member 'UUI_VoteProgress_C::Image_246' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, MapInfo) == 0x000280, "Member 'UUI_VoteProgress_C::MapInfo' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, MapSubText) == 0x000288, "Member 'UUI_VoteProgress_C::MapSubText' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, MapText) == 0x000290, "Member 'UUI_VoteProgress_C::MapText' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Team1Subtext) == 0x000298, "Member 'UUI_VoteProgress_C::Team1Subtext' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Team1Text) == 0x0002A0, "Member 'UUI_VoteProgress_C::Team1Text' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Team2Subtext) == 0x0002A8, "Member 'UUI_VoteProgress_C::Team2Subtext' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, Team2Text) == 0x0002B0, "Member 'UUI_VoteProgress_C::Team2Text' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, MainTextList) == 0x0002B8, "Member 'UUI_VoteProgress_C::MainTextList' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, SubTextList) == 0x0002C8, "Member 'UUI_VoteProgress_C::SubTextList' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, RequestMapInfo) == 0x0002D8, "Member 'UUI_VoteProgress_C::RequestMapInfo' has a wrong offset!");
static_assert(offsetof(UUI_VoteProgress_C, RequestFactionInfo) == 0x0002E8, "Member 'UUI_VoteProgress_C::RequestFactionInfo' has a wrong offset!");

}

