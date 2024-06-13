#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SkinRestrictionsData

#include "Basic.hpp"

#include "ESQBiome_structs.hpp"


namespace SDK
{

// UserDefinedStruct SkinRestrictionsData.SkinRestrictionsData
// 0x00A8 (0x00A8 - 0x0000)
struct FSkinRestrictionsData final
{
public:
	TSet<ESQBiome>                                AllowedBiomes_4_8456035E44967A2909CAFC9864F1AA70;  // 0x0000(0x0050)(Edit, BlueprintVisible)
	TSet<TSoftObjectPtr<class UBP_SQFactionSetup_C>> AllowedFactionSetups_21_798013FF4193B4DF4FDCA68D5C74C4A0; // 0x0050(0x0050)(Edit, BlueprintVisible)
	bool                                          bForceDisableOthers_27_F7F7AB124635451B1DF147B1557AB4F7; // 0x00A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(FSkinRestrictionsData) == 0x000008, "Wrong alignment on FSkinRestrictionsData");
static_assert(sizeof(FSkinRestrictionsData) == 0x0000A8, "Wrong size on FSkinRestrictionsData");
static_assert(offsetof(FSkinRestrictionsData, AllowedBiomes_4_8456035E44967A2909CAFC9864F1AA70) == 0x000000, "Member 'FSkinRestrictionsData::AllowedBiomes_4_8456035E44967A2909CAFC9864F1AA70' has a wrong offset!");
static_assert(offsetof(FSkinRestrictionsData, AllowedFactionSetups_21_798013FF4193B4DF4FDCA68D5C74C4A0) == 0x000050, "Member 'FSkinRestrictionsData::AllowedFactionSetups_21_798013FF4193B4DF4FDCA68D5C74C4A0' has a wrong offset!");
static_assert(offsetof(FSkinRestrictionsData, bForceDisableOthers_27_F7F7AB124635451B1DF147B1557AB4F7) == 0x0000A0, "Member 'FSkinRestrictionsData::bForceDisableOthers_27_F7F7AB124635451B1DF147B1557AB4F7' has a wrong offset!");

}

