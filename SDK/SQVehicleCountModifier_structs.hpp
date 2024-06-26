#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQVehicleCountModifier

#include "Basic.hpp"

#include "ESQVehicle_structs.hpp"
#include "ESQVehicleTag_structs.hpp"


namespace SDK
{

// UserDefinedStruct SQVehicleCountModifier.SQVehicleCountModifier
// 0x00A8 (0x00A8 - 0x0000)
struct FSQVehicleCountModifier final
{
public:
	TSet<ESQVehicle>                              TargetType_7_F90601ED40463964DEF8C0A76ED3DFB7;     // 0x0000(0x0050)(Edit, BlueprintVisible)
	TSet<ESQVehicleTag>                           TargetTags_3_5DD977BA42F28411830DF39CC6BC5865;     // 0x0050(0x0050)(Edit, BlueprintVisible)
	int32                                         Modifier_12_AD280A0344E05118EF7C028BE593AC98;      // 0x00A0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FSQVehicleCountModifier) == 0x000008, "Wrong alignment on FSQVehicleCountModifier");
static_assert(sizeof(FSQVehicleCountModifier) == 0x0000A8, "Wrong size on FSQVehicleCountModifier");
static_assert(offsetof(FSQVehicleCountModifier, TargetType_7_F90601ED40463964DEF8C0A76ED3DFB7) == 0x000000, "Member 'FSQVehicleCountModifier::TargetType_7_F90601ED40463964DEF8C0A76ED3DFB7' has a wrong offset!");
static_assert(offsetof(FSQVehicleCountModifier, TargetTags_3_5DD977BA42F28411830DF39CC6BC5865) == 0x000050, "Member 'FSQVehicleCountModifier::TargetTags_3_5DD977BA42F28411830DF39CC6BC5865' has a wrong offset!");
static_assert(offsetof(FSQVehicleCountModifier, Modifier_12_AD280A0344E05118EF7C028BE593AC98) == 0x0000A0, "Member 'FSQVehicleCountModifier::Modifier_12_AD280A0344E05118EF7C028BE593AC98' has a wrong offset!");

}

