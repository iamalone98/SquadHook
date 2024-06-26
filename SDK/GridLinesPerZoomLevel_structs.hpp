#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: GridLinesPerZoomLevel

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK
{

// UserDefinedStruct GridLinesPerZoomLevel.GridLinesPerZoomLevel
// 0x0030 (0x0030 - 0x0000)
struct FGridLinesPerZoomLevel final
{
public:
	class UCurveFloat*                            OpacityPerZoom_8_7D4D594647988B210638DCA367C8F9DA; // 0x0000(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Texture_2_513F535945D2FFFAA449FA922C520958;        // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ZoomAmountBegin_20_CCBF4CDF4CB0084B153CAEA044D4CA18; // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ZoomAmountEnd_21_972E750A4C1ACB475F9EE7B38D389776; // 0x0014(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         ScaleFactor_25_1F6A722B4DB5237162393799FF69B000;   // 0x0018(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Tint_28_C16F00104057164EAE6283B19B77017E;          // 0x001C(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FGridLinesPerZoomLevel) == 0x000008, "Wrong alignment on FGridLinesPerZoomLevel");
static_assert(sizeof(FGridLinesPerZoomLevel) == 0x000030, "Wrong size on FGridLinesPerZoomLevel");
static_assert(offsetof(FGridLinesPerZoomLevel, OpacityPerZoom_8_7D4D594647988B210638DCA367C8F9DA) == 0x000000, "Member 'FGridLinesPerZoomLevel::OpacityPerZoom_8_7D4D594647988B210638DCA367C8F9DA' has a wrong offset!");
static_assert(offsetof(FGridLinesPerZoomLevel, Texture_2_513F535945D2FFFAA449FA922C520958) == 0x000008, "Member 'FGridLinesPerZoomLevel::Texture_2_513F535945D2FFFAA449FA922C520958' has a wrong offset!");
static_assert(offsetof(FGridLinesPerZoomLevel, ZoomAmountBegin_20_CCBF4CDF4CB0084B153CAEA044D4CA18) == 0x000010, "Member 'FGridLinesPerZoomLevel::ZoomAmountBegin_20_CCBF4CDF4CB0084B153CAEA044D4CA18' has a wrong offset!");
static_assert(offsetof(FGridLinesPerZoomLevel, ZoomAmountEnd_21_972E750A4C1ACB475F9EE7B38D389776) == 0x000014, "Member 'FGridLinesPerZoomLevel::ZoomAmountEnd_21_972E750A4C1ACB475F9EE7B38D389776' has a wrong offset!");
static_assert(offsetof(FGridLinesPerZoomLevel, ScaleFactor_25_1F6A722B4DB5237162393799FF69B000) == 0x000018, "Member 'FGridLinesPerZoomLevel::ScaleFactor_25_1F6A722B4DB5237162393799FF69B000' has a wrong offset!");
static_assert(offsetof(FGridLinesPerZoomLevel, Tint_28_C16F00104057164EAE6283B19B77017E) == 0x00001C, "Member 'FGridLinesPerZoomLevel::Tint_28_C16F00104057164EAE6283B19B77017E' has a wrong offset!");

}

