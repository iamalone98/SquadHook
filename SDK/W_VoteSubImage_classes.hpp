#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_VoteSubImage

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_VoteSubImage.W_VoteSubImage_C
// 0x0060 (0x02C0 - 0x0260)
class UW_VoteSubImage_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBorder*                                Background;                                        // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Tag_Image;                                         // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              Content;                                           // 0x0278(0x0028)(Edit, BlueprintVisible, ExposeOnSpawn, HasGetValueTypeHash)
	struct FLinearColor                           ContentColor;                                      // 0x02A0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	struct FLinearColor                           BackgroundColor;                                   // 0x02B0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_VoteSubImage(int32 EntryPoint);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_VoteSubImage_C">();
	}
	static class UW_VoteSubImage_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_VoteSubImage_C>();
	}
};
static_assert(alignof(UW_VoteSubImage_C) == 0x000008, "Wrong alignment on UW_VoteSubImage_C");
static_assert(sizeof(UW_VoteSubImage_C) == 0x0002C0, "Wrong size on UW_VoteSubImage_C");
static_assert(offsetof(UW_VoteSubImage_C, UberGraphFrame) == 0x000260, "Member 'UW_VoteSubImage_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_VoteSubImage_C, Background) == 0x000268, "Member 'UW_VoteSubImage_C::Background' has a wrong offset!");
static_assert(offsetof(UW_VoteSubImage_C, Tag_Image) == 0x000270, "Member 'UW_VoteSubImage_C::Tag_Image' has a wrong offset!");
static_assert(offsetof(UW_VoteSubImage_C, Content) == 0x000278, "Member 'UW_VoteSubImage_C::Content' has a wrong offset!");
static_assert(offsetof(UW_VoteSubImage_C, ContentColor) == 0x0002A0, "Member 'UW_VoteSubImage_C::ContentColor' has a wrong offset!");
static_assert(offsetof(UW_VoteSubImage_C, BackgroundColor) == 0x0002B0, "Member 'UW_VoteSubImage_C::BackgroundColor' has a wrong offset!");

}
