#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SQAvailability_Role

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_SQAvailability_Role.BP_SQAvailability_Role_C
// 0x0000 (0x0058 - 0x0058)
class UBP_SQAvailability_Role_C final : public USQAvailability_Role
{
public:
	int32 GetRearmRefundPercentage() const;
	struct FDataTableRowHandle GetInsufficientAmmoReamFailureReason() const;
	void GetAvailabilityForPlayer(class ASQPlayerController* InPlayer, const struct FSQAvailabilityState& InTeamStatus, struct FSQAvailabilityState* OutPlayerStatus) const;
	void UpdateTeamAvailability(class ASQTeam* InTeam, struct FSQAvailabilityState* OutTeamStatus) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_SQAvailability_Role_C">();
	}
	static class UBP_SQAvailability_Role_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_SQAvailability_Role_C>();
	}
};
static_assert(alignof(UBP_SQAvailability_Role_C) == 0x000008, "Wrong alignment on UBP_SQAvailability_Role_C");
static_assert(sizeof(UBP_SQAvailability_Role_C) == 0x000058, "Wrong size on UBP_SQAvailability_Role_C");

}
