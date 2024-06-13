#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQActionEntry

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK
{

// UserDefinedStruct SQActionEntry.SQActionEntry
// 0x0050 (0x0050 - 0x0000)
struct FSQActionEntry final
{
public:
	class FText                                   DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625;    // 0x0000(0x0018)(Edit, BlueprintVisible)
	class FText                                   Details_5_05E7EAEF4F1306A917C5A4837F8F40D0;        // 0x0018(0x0018)(Edit, BlueprintVisible)
	class UTexture2D*                             Icon_10_CEC409E14C155F9F18EC1C961848686E;          // 0x0030(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63;       // 0x0038(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Tint_15_974BD2F241A0E0ED7FEB65B634A8F44E;          // 0x0040(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FSQActionEntry) == 0x000008, "Wrong alignment on FSQActionEntry");
static_assert(sizeof(FSQActionEntry) == 0x000050, "Wrong size on FSQActionEntry");
static_assert(offsetof(FSQActionEntry, DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625) == 0x000000, "Member 'FSQActionEntry::DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625' has a wrong offset!");
static_assert(offsetof(FSQActionEntry, Details_5_05E7EAEF4F1306A917C5A4837F8F40D0) == 0x000018, "Member 'FSQActionEntry::Details_5_05E7EAEF4F1306A917C5A4837F8F40D0' has a wrong offset!");
static_assert(offsetof(FSQActionEntry, Icon_10_CEC409E14C155F9F18EC1C961848686E) == 0x000030, "Member 'FSQActionEntry::Icon_10_CEC409E14C155F9F18EC1C961848686E' has a wrong offset!");
static_assert(offsetof(FSQActionEntry, MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63) == 0x000038, "Member 'FSQActionEntry::MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63' has a wrong offset!");
static_assert(offsetof(FSQActionEntry, Tint_15_974BD2F241A0E0ED7FEB65B634A8F44E) == 0x000040, "Member 'FSQActionEntry::Tint_15_974BD2F241A0E0ED7FEB65B634A8F44E' has a wrong offset!");

}

