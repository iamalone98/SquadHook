#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQDeployableEntry

#include "Basic.hpp"

#include "ESQDeployableCategory_structs.hpp"


namespace SDK
{

// UserDefinedStruct SQDeployableEntry.SQDeployableEntry
// 0x0068 (0x0068 - 0x0000)
struct FSQDeployableEntry final
{
public:
	class FText                                   DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625;    // 0x0000(0x0018)(Edit, BlueprintVisible)
	class FText                                   Details_5_05E7EAEF4F1306A917C5A4837F8F40D0;        // 0x0018(0x0018)(Edit, BlueprintVisible)
	class FText                                   ToolTip_20_184DD04A4D44CF9D518A218A50B31AA6;       // 0x0030(0x0018)(Edit, BlueprintVisible)
	class UTexture2D*                             Icon_17_CEC409E14C155F9F18EC1C961848686E;          // 0x0048(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63;       // 0x0050(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQDeployableCategory                         Category_18_2720347E4A0B7CEC6E8B90B886DD63BA;      // 0x0058(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_45D0[0x3];                                     // 0x0059(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   Text_Key0_25_02C3C41A45679AF5531078A0BCEB74B0;     // 0x005C(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FSQDeployableEntry) == 0x000008, "Wrong alignment on FSQDeployableEntry");
static_assert(sizeof(FSQDeployableEntry) == 0x000068, "Wrong size on FSQDeployableEntry");
static_assert(offsetof(FSQDeployableEntry, DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625) == 0x000000, "Member 'FSQDeployableEntry::DisplayName_2_AE20EB5F4F79C0010BCDCE847B39E625' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, Details_5_05E7EAEF4F1306A917C5A4837F8F40D0) == 0x000018, "Member 'FSQDeployableEntry::Details_5_05E7EAEF4F1306A917C5A4837F8F40D0' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, ToolTip_20_184DD04A4D44CF9D518A218A50B31AA6) == 0x000030, "Member 'FSQDeployableEntry::ToolTip_20_184DD04A4D44CF9D518A218A50B31AA6' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, Icon_17_CEC409E14C155F9F18EC1C961848686E) == 0x000048, "Member 'FSQDeployableEntry::Icon_17_CEC409E14C155F9F18EC1C961848686E' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63) == 0x000050, "Member 'FSQDeployableEntry::MapIcon_12_A944622A487C1C56FFF28F97F2A5CD63' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, Category_18_2720347E4A0B7CEC6E8B90B886DD63BA) == 0x000058, "Member 'FSQDeployableEntry::Category_18_2720347E4A0B7CEC6E8B90B886DD63BA' has a wrong offset!");
static_assert(offsetof(FSQDeployableEntry, Text_Key0_25_02C3C41A45679AF5531078A0BCEB74B0) == 0x00005C, "Member 'FSQDeployableEntry::Text_Key0_25_02C3C41A45679AF5531078A0BCEB74B0' has a wrong offset!");

}

