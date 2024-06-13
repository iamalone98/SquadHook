#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ruleset_Vehicle

#include "Basic.hpp"

#include "TeamVehicleRuleelement_structs.hpp"
#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "ESQVehicleTag_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Ruleset_Vehicle.BP_Ruleset_Vehicle_C
// 0x0020 (0x0278 - 0x0258)
class ABP_Ruleset_Vehicle_C final : public ASQGameRuleSet
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0258(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0260(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	TArray<struct FTeamVehicleRuleElement>        Rules;                                             // 0x0268(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_BP_Ruleset_Vehicle(int32 EntryPoint);
	void VehicleDestroyed(class ASQPlayerController* Killer, class ASQPlayerController* Victim, class ASQVehicle* DestroyedVehicle);
	void ApplyRules(TArray<struct FVehicleRuleElement>& In_Vehicle_Rule, class UBP_SQVehicleSettings_C* In_Vehicle_Settings, class ASQPlayerController* In_Killer, class ASQTeamState* In_Victim_TeamState, class ASQTeamState* In_Kill_Instigator_TeamState);
	void GetInstigatorTeamState(class ASQPlayerController* In_Killer, class ASQPlayerController* In_Victim, class ASQVehicle* In_Vehicle, bool* Out_Success, class ASQTeamState** Out_TeamState);
	void GetVictimTeamState(class ASQPlayerController* In_Killer, class ASQPlayerController* In_Victim, class ASQVehicle* In_Vehicle, bool* Out_Success, class ASQTeamState** Out_TeamState);

	void FindRuleList(int32 In_TeamId, ESQTeamRelationShip In_Relationship, bool* Out_Found, struct FTeamVehicleRuleElement* Out_Rule) const;
	void FindRules(const struct FTeamVehicleRuleElement& In_Team_Rule, class UBP_SQVehicleSettings_C* In_Vehicle_Setting, TArray<struct FVehicleRuleElement>* Out_Rules) const;
	void GetPointsForVehicleKill(int32 In_TeamId, class UBP_SQVehicleSettings_C* In_Vehicle_Settings, int32* Out_Points) const;
	void SelectRules(int32 In_Kill_Instigator_Team_ID, int32 In_Victim_Team_ID, class UBP_SQVehicleSettings_C* In_Vehicle_Settings, TArray<struct FVehicleRuleElement>* Out_Rules) const;
	void GetTicketsForVehicleKill(int32 In_TeamId, class UBP_SQVehicleSettings_C* In_Vehicle_Settings, int32* Out_Tickets) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Ruleset_Vehicle_C">();
	}
	static class ABP_Ruleset_Vehicle_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Ruleset_Vehicle_C>();
	}
};
static_assert(alignof(ABP_Ruleset_Vehicle_C) == 0x000008, "Wrong alignment on ABP_Ruleset_Vehicle_C");
static_assert(sizeof(ABP_Ruleset_Vehicle_C) == 0x000278, "Wrong size on ABP_Ruleset_Vehicle_C");
static_assert(offsetof(ABP_Ruleset_Vehicle_C, UberGraphFrame) == 0x000258, "Member 'ABP_Ruleset_Vehicle_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_Ruleset_Vehicle_C, DefaultSceneRoot) == 0x000260, "Member 'ABP_Ruleset_Vehicle_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_Ruleset_Vehicle_C, Rules) == 0x000268, "Member 'ABP_Ruleset_Vehicle_C::Rules' has a wrong offset!");

}

