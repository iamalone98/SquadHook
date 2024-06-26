#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQLayerTeamConfig

#include "Basic.hpp"

#include "SQEAlliance_structs.hpp"
#include "ESQFactionSetupType_structs.hpp"
#include "ESQFactionSetupTag_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQLayerTeamConfig.BP_SQLayerTeamConfig_C
// 0x00F8 (0x0158 - 0x0060)
class UBP_SQLayerTeamConfig_C final : public USQLayerTeamConfig
{
public:
	bool                                          DisableVehicleDuringStaggingPhase;                 // 0x0060(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2C41[0x7];                                     // 0x0061(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	TSet<ESQEAlliance>                            Allowed_Alliances;                                 // 0x0068(0x0050)(Edit, BlueprintVisible)
	TSet<ESQFactionSetupType>                     AllowedFactionSetupTypes;                          // 0x00B8(0x0050)(Edit, BlueprintVisible)
	TSet<ESQFactionSetupTag>                      RequiredTags;                                      // 0x0108(0x0050)(Edit, BlueprintVisible, BlueprintReadOnly)

public:
	void IsAttackingTeam(bool* Param_IsAttackingTeam) const;
	void IsDefendingTeam(bool* IsDefendngTeam) const;
	bool EditorOnly_ShouldUseSpecificFaction() const;
	bool GetCompatibleFactionSetups(const class USQLayer* InOuterLayer, const TMap<class FName, class USQFactionSetup*>& InAvailableFactionSetups, TArray<class USQFactionSetup*>* OutCompatibleFactionSetups) const;
	bool HasFactionSetupChoice(const class USQLayer* InOuterLayer, class USQFactionSetup** OutSpecificFaction, const TArray<class FName>& Excluded) const;
	bool CanUseFaction(const class USQFactionSetup* SQFaction) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQLayerTeamConfig_C">();
	}
	static class UBP_SQLayerTeamConfig_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQLayerTeamConfig_C>();
	}
};
static_assert(alignof(UBP_SQLayerTeamConfig_C) == 0x000008, "Wrong alignment on UBP_SQLayerTeamConfig_C");
static_assert(sizeof(UBP_SQLayerTeamConfig_C) == 0x000158, "Wrong size on UBP_SQLayerTeamConfig_C");
static_assert(offsetof(UBP_SQLayerTeamConfig_C, DisableVehicleDuringStaggingPhase) == 0x000060, "Member 'UBP_SQLayerTeamConfig_C::DisableVehicleDuringStaggingPhase' has a wrong offset!");
static_assert(offsetof(UBP_SQLayerTeamConfig_C, Allowed_Alliances) == 0x000068, "Member 'UBP_SQLayerTeamConfig_C::Allowed_Alliances' has a wrong offset!");
static_assert(offsetof(UBP_SQLayerTeamConfig_C, AllowedFactionSetupTypes) == 0x0000B8, "Member 'UBP_SQLayerTeamConfig_C::AllowedFactionSetupTypes' has a wrong offset!");
static_assert(offsetof(UBP_SQLayerTeamConfig_C, RequiredTags) == 0x000108, "Member 'UBP_SQLayerTeamConfig_C::RequiredTags' has a wrong offset!");

}

