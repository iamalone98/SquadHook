#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_FactionFlagSmall

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_FactionFlagSmall.W_FactionFlagSmall_C
// 0x0058 (0x02B8 - 0x0260)
class UW_FactionFlagSmall_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Image_31;                                          // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_0;                                         // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TSoftObjectPtr<class UTexture2D>              Soft_Texture;                                      // 0x0278(0x0028)(Edit, BlueprintVisible, ExposeOnSpawn, UObjectWrapper, HasGetValueTypeHash)
	class FText                                   FactionName;                                       // 0x02A0(0x0018)(Edit, BlueprintVisible, ExposeOnSpawn)

public:
	void ExecuteUbergraph_W_FactionFlagSmall(int32 EntryPoint);
	void Construct();
	class UWidget* GetToolTipWidget_0();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_FactionFlagSmall_C">();
	}
	static class UW_FactionFlagSmall_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_FactionFlagSmall_C>();
	}
};
static_assert(alignof(UW_FactionFlagSmall_C) == 0x000008, "Wrong alignment on UW_FactionFlagSmall_C");
static_assert(sizeof(UW_FactionFlagSmall_C) == 0x0002B8, "Wrong size on UW_FactionFlagSmall_C");
static_assert(offsetof(UW_FactionFlagSmall_C, UberGraphFrame) == 0x000260, "Member 'UW_FactionFlagSmall_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_FactionFlagSmall_C, Image_31) == 0x000268, "Member 'UW_FactionFlagSmall_C::Image_31' has a wrong offset!");
static_assert(offsetof(UW_FactionFlagSmall_C, SizeBox_0) == 0x000270, "Member 'UW_FactionFlagSmall_C::SizeBox_0' has a wrong offset!");
static_assert(offsetof(UW_FactionFlagSmall_C, Soft_Texture) == 0x000278, "Member 'UW_FactionFlagSmall_C::Soft_Texture' has a wrong offset!");
static_assert(offsetof(UW_FactionFlagSmall_C, FactionName) == 0x0002A0, "Member 'UW_FactionFlagSmall_C::FactionName' has a wrong offset!");

}
