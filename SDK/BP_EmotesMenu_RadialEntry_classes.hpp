#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_EmotesMenu_RadialEntry

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_RadialActionModel_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_EmotesMenu_RadialEntry.BP_EmotesMenu_RadialEntry_C
// 0x0018 (0x00C0 - 0x00A8)
class UBP_EmotesMenu_RadialEntry_C final : public UBP_RadialActionModel_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_EmotesMenu_RadialEntry_C;        // 0x00A8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQEmotesData*                          EmoteItem;                                         // 0x00B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         EmoteIndex;                                        // 0x00B8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_EmotesMenu_RadialEntry(int32 EntryPoint);
	void OnClicked(class UBaseRadialMenu_C* Radial);
	TArray<class FString> CanClick(class ASQPlayerController* PC, bool* bCanClick);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_EmotesMenu_RadialEntry_C">();
	}
	static class UBP_EmotesMenu_RadialEntry_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_EmotesMenu_RadialEntry_C>();
	}
};
static_assert(alignof(UBP_EmotesMenu_RadialEntry_C) == 0x000008, "Wrong alignment on UBP_EmotesMenu_RadialEntry_C");
static_assert(sizeof(UBP_EmotesMenu_RadialEntry_C) == 0x0000C0, "Wrong size on UBP_EmotesMenu_RadialEntry_C");
static_assert(offsetof(UBP_EmotesMenu_RadialEntry_C, UberGraphFrame_BP_EmotesMenu_RadialEntry_C) == 0x0000A8, "Member 'UBP_EmotesMenu_RadialEntry_C::UberGraphFrame_BP_EmotesMenu_RadialEntry_C' has a wrong offset!");
static_assert(offsetof(UBP_EmotesMenu_RadialEntry_C, EmoteItem) == 0x0000B0, "Member 'UBP_EmotesMenu_RadialEntry_C::EmoteItem' has a wrong offset!");
static_assert(offsetof(UBP_EmotesMenu_RadialEntry_C, EmoteIndex) == 0x0000B8, "Member 'UBP_EmotesMenu_RadialEntry_C::EmoteIndex' has a wrong offset!");

}

