#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_StoreCard

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_StoreCard.W_StoreCard_C
// 0x0090 (0x0338 - 0x02A8)
class UW_StoreCard_C final : public USQUserWidget_StoreCard
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x02A8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       NewLoop;                                           // 0x02B0(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       Hover;                                             // 0x02B8(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 DetailGradient;                                    // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DropShadow;                                        // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_359;                                         // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              CardTexture;                                       // 0x02D8(0x0028)(Edit, BlueprintVisible, ExposeOnSpawn, HasGetValueTypeHash)
	class FText                                   TitleText;                                         // 0x0300(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	class FText                                   DescriptionText;                                   // 0x0318(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	bool                                          bIsOnSale;                                         // 0x0330(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          bIsNew;                                            // 0x0331(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)

public:
	void ExecuteUbergraph_W_StoreCard(int32 EntryPoint);
	void Construct();
	void BndEvt__Button_0_K2Node_ComponentBoundEvent_2_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_0_K2Node_ComponentBoundEvent_1_OnButtonHoverEvent__DelegateSignature();
	ESlateVisibility GetVisibility_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_StoreCard_C">();
	}
	static class UW_StoreCard_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_StoreCard_C>();
	}
};
static_assert(alignof(UW_StoreCard_C) == 0x000008, "Wrong alignment on UW_StoreCard_C");
static_assert(sizeof(UW_StoreCard_C) == 0x000338, "Wrong size on UW_StoreCard_C");
static_assert(offsetof(UW_StoreCard_C, UberGraphFrame) == 0x0002A8, "Member 'UW_StoreCard_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, NewLoop) == 0x0002B0, "Member 'UW_StoreCard_C::NewLoop' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, Hover) == 0x0002B8, "Member 'UW_StoreCard_C::Hover' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, DetailGradient) == 0x0002C0, "Member 'UW_StoreCard_C::DetailGradient' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, DropShadow) == 0x0002C8, "Member 'UW_StoreCard_C::DropShadow' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, Image_359) == 0x0002D0, "Member 'UW_StoreCard_C::Image_359' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, CardTexture) == 0x0002D8, "Member 'UW_StoreCard_C::CardTexture' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, TitleText) == 0x000300, "Member 'UW_StoreCard_C::TitleText' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, DescriptionText) == 0x000318, "Member 'UW_StoreCard_C::DescriptionText' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, bIsOnSale) == 0x000330, "Member 'UW_StoreCard_C::bIsOnSale' has a wrong offset!");
static_assert(offsetof(UW_StoreCard_C, bIsNew) == 0x000331, "Member 'UW_StoreCard_C::bIsNew' has a wrong offset!");

}
