#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQDeployableGroupingStrategy

#include "Basic.hpp"

#include "ESQDeployableTag_structs.hpp"


namespace SDK
{

// UserDefinedStruct SQDeployableGroupingStrategy.SQDeployableGroupingStrategy
// 0x0090 (0x0090 - 0x0000)
struct FSQDeployableGroupingStrategy final
{
public:
	class FText                                   DisplayName_2_F99B8C43430BAF4FF50FAB9079014748;    // 0x0000(0x0018)(Edit, BlueprintVisible)
	class FText                                   Description_20_9D063CFC4D56524A453A7891125E6AE6;   // 0x0018(0x0018)(Edit, BlueprintVisible)
	class UTexture2D*                             Icon_16_47DBEEF44044C91E422315AE8AD2307D;          // 0x0030(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TSet<ESQDeployableTag>                        TargetTags_15_7D977F504B2C80DD6EBF01A470463DAD;    // 0x0038(0x0050)(Edit, BlueprintVisible)
	bool                                          ReversedRule_12_548311FD4F326FC0DCFF66B6B6DBBC70;  // 0x0088(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
};
static_assert(alignof(FSQDeployableGroupingStrategy) == 0x000008, "Wrong alignment on FSQDeployableGroupingStrategy");
static_assert(sizeof(FSQDeployableGroupingStrategy) == 0x000090, "Wrong size on FSQDeployableGroupingStrategy");
static_assert(offsetof(FSQDeployableGroupingStrategy, DisplayName_2_F99B8C43430BAF4FF50FAB9079014748) == 0x000000, "Member 'FSQDeployableGroupingStrategy::DisplayName_2_F99B8C43430BAF4FF50FAB9079014748' has a wrong offset!");
static_assert(offsetof(FSQDeployableGroupingStrategy, Description_20_9D063CFC4D56524A453A7891125E6AE6) == 0x000018, "Member 'FSQDeployableGroupingStrategy::Description_20_9D063CFC4D56524A453A7891125E6AE6' has a wrong offset!");
static_assert(offsetof(FSQDeployableGroupingStrategy, Icon_16_47DBEEF44044C91E422315AE8AD2307D) == 0x000030, "Member 'FSQDeployableGroupingStrategy::Icon_16_47DBEEF44044C91E422315AE8AD2307D' has a wrong offset!");
static_assert(offsetof(FSQDeployableGroupingStrategy, TargetTags_15_7D977F504B2C80DD6EBF01A470463DAD) == 0x000038, "Member 'FSQDeployableGroupingStrategy::TargetTags_15_7D977F504B2C80DD6EBF01A470463DAD' has a wrong offset!");
static_assert(offsetof(FSQDeployableGroupingStrategy, ReversedRule_12_548311FD4F326FC0DCFF66B6B6DBBC70) == 0x000088, "Member 'FSQDeployableGroupingStrategy::ReversedRule_12_548311FD4F326FC0DCFF66B6B6DBBC70' has a wrong offset!");

}
