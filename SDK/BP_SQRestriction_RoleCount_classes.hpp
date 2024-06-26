#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQRestriction_RoleCount

#include "Basic.hpp"

#include "SQRoleTags_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQRestriction_RoleCount.BP_SQRestriction_RoleCount_C
// 0x00A0 (0x0118 - 0x0078)
class UBP_SQRestriction_RoleCount_C final : public USQRestriction_Count
{
public:
	TSet<ESQRoleTags>                             Target_Role_Tags;                                  // 0x0078(0x0050)(Edit, BlueprintVisible, BlueprintReadOnly)
	TSet<ESQRoleTags>                             Excluded_Role_Tags;                                // 0x00C8(0x0050)(Edit, BlueprintVisible, BlueprintReadOnly)

public:
	void ShouldBeCounted(class USQRoleSettings* In_Tested_Role_Setting, class USQRoleSettings* In_Searched_Role_Setting_If_No_Tags, bool* Out_Should_Be_Counted);
	void GetTeamUsage(class ASQTeam* In_Team, class USQRoleSettings* In_Setting, int32* Out_Usage);
	void GetSquadUsage(class ASQPlayerController* In_Player, class USQRoleSettings* In_Setting, int32* Out_Usage);
	void ShouldPlayerBeCounted(class ASQPlayerState* In_Player, class USQRoleSettings* In_Searched_Role_Setting_If_No_Tags, bool* Out_Should_Count);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQRestriction_RoleCount_C">();
	}
	static class UBP_SQRestriction_RoleCount_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQRestriction_RoleCount_C>();
	}
};
static_assert(alignof(UBP_SQRestriction_RoleCount_C) == 0x000008, "Wrong alignment on UBP_SQRestriction_RoleCount_C");
static_assert(sizeof(UBP_SQRestriction_RoleCount_C) == 0x000118, "Wrong size on UBP_SQRestriction_RoleCount_C");
static_assert(offsetof(UBP_SQRestriction_RoleCount_C, Target_Role_Tags) == 0x000078, "Member 'UBP_SQRestriction_RoleCount_C::Target_Role_Tags' has a wrong offset!");
static_assert(offsetof(UBP_SQRestriction_RoleCount_C, Excluded_Role_Tags) == 0x0000C8, "Member 'UBP_SQRestriction_RoleCount_C::Excluded_Role_Tags' has a wrong offset!");

}

