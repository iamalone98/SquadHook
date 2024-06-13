#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_InfoWidget

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_InfoWidget.W_InfoWidget_C
// 0x00E0 (0x0340 - 0x0260)
class UW_InfoWidget_C final : public USQAnnouncementNotifier
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                BottomBorder;                                      // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DetailGradient;                                    // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_62;                                          // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_237;                                         // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_Icon;                                        // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USQRichTextBlock*                       SQRichBodyText;                                    // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TitleText;                                         // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                TopBorder;                                         // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   HeadingText;                                       // 0x02B0(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	class FText                                   BodyText;                                          // 0x02C8(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)
	TSoftObjectPtr<class UTexture2D>              BackgroundTexture;                                 // 0x02E0(0x0028)(Edit, BlueprintVisible, ExposeOnSpawn, UObjectWrapper, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              IconTexture;                                       // 0x0308(0x0028)(Edit, BlueprintVisible, ExposeOnSpawn, UObjectWrapper, HasGetValueTypeHash)
	struct FLinearColor                           ColourTint;                                        // 0x0330(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_InfoWidget(int32 EntryPoint);
	void Construct();
	void PreConstruct(bool IsDesignTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_InfoWidget_C">();
	}
	static class UW_InfoWidget_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_InfoWidget_C>();
	}
};
static_assert(alignof(UW_InfoWidget_C) == 0x000008, "Wrong alignment on UW_InfoWidget_C");
static_assert(sizeof(UW_InfoWidget_C) == 0x000340, "Wrong size on UW_InfoWidget_C");
static_assert(offsetof(UW_InfoWidget_C, UberGraphFrame) == 0x000260, "Member 'UW_InfoWidget_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, BottomBorder) == 0x000268, "Member 'UW_InfoWidget_C::BottomBorder' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, DetailGradient) == 0x000270, "Member 'UW_InfoWidget_C::DetailGradient' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, Image) == 0x000278, "Member 'UW_InfoWidget_C::Image' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, Image_62) == 0x000280, "Member 'UW_InfoWidget_C::Image_62' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, Image_237) == 0x000288, "Member 'UW_InfoWidget_C::Image_237' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, Image_Icon) == 0x000290, "Member 'UW_InfoWidget_C::Image_Icon' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, SQRichBodyText) == 0x000298, "Member 'UW_InfoWidget_C::SQRichBodyText' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, TitleText) == 0x0002A0, "Member 'UW_InfoWidget_C::TitleText' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, TopBorder) == 0x0002A8, "Member 'UW_InfoWidget_C::TopBorder' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, HeadingText) == 0x0002B0, "Member 'UW_InfoWidget_C::HeadingText' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, BodyText) == 0x0002C8, "Member 'UW_InfoWidget_C::BodyText' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, BackgroundTexture) == 0x0002E0, "Member 'UW_InfoWidget_C::BackgroundTexture' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, IconTexture) == 0x000308, "Member 'UW_InfoWidget_C::IconTexture' has a wrong offset!");
static_assert(offsetof(UW_InfoWidget_C, ColourTint) == 0x000330, "Member 'UW_InfoWidget_C::ColourTint' has a wrong offset!");

}

