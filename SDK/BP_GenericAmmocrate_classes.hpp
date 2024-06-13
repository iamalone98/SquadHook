#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericAmmocrate

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "BP_SmartDeployable_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_GenericAmmocrate.BP_GenericAmmocrate_C
// 0x0010 (0x0460 - 0x0450)
class ABP_GenericAmmocrate_C : public ABP_SmartDeployable_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_GenericAmmocrate_C;              // 0x0450(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQMapIconComponent*                    SquadMapIcon;                                      // 0x0458(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_GenericAmmocrate(int32 EntryPoint);
	void SetTeam(int32 Param_Team);
	bool UnbindEventToAmmoUpdated(const TDelegate<void()>& Delegate);
	class FString GetRearmSuccessString();
	class FString GetRearmNoAmmoString();
	bool ConsumeAmmo(float AmmoRequired);
	bool BindEventToAmmoUpdated(const TDelegate<void()>& Delegate);

	ESQRearmType GetRearmType() const;
	float GetAmmo() const;
	bool CanRearmWeapon(const class ASQEquipableItem* Weapon) const;
	bool CanRearmPawn(const class APawn* Rearmer) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericAmmocrate_C">();
	}
	static class ABP_GenericAmmocrate_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_GenericAmmocrate_C>();
	}
};
static_assert(alignof(ABP_GenericAmmocrate_C) == 0x000008, "Wrong alignment on ABP_GenericAmmocrate_C");
static_assert(sizeof(ABP_GenericAmmocrate_C) == 0x000460, "Wrong size on ABP_GenericAmmocrate_C");
static_assert(offsetof(ABP_GenericAmmocrate_C, UberGraphFrame_BP_GenericAmmocrate_C) == 0x000450, "Member 'ABP_GenericAmmocrate_C::UberGraphFrame_BP_GenericAmmocrate_C' has a wrong offset!");
static_assert(offsetof(ABP_GenericAmmocrate_C, SquadMapIcon) == 0x000458, "Member 'ABP_GenericAmmocrate_C::SquadMapIcon' has a wrong offset!");

}
