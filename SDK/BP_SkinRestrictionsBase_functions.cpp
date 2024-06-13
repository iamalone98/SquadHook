#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_SkinRestrictionsBase

#include "Basic.hpp"

#include "BP_SkinRestrictionsBase_classes.hpp"
#include "BP_SkinRestrictionsBase_parameters.hpp"


namespace SDK
{

// Function BP_SkinRestrictionsBase.BP_SkinRestrictionsBase_C.IsValidForCurrentConditions
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// struct FSQItemSkinRestrictionParameters Params_0                                               (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UBP_SkinRestrictionsBase_C::IsValidForCurrentConditions(const struct FSQItemSkinRestrictionParameters& Params_0) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SkinRestrictionsBase_C", "IsValidForCurrentConditions");

	Params::BP_SkinRestrictionsBase_C_IsValidForCurrentConditions Parms{};

	Parms.Params_0 = std::move(Params_0);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function BP_SkinRestrictionsBase.BP_SkinRestrictionsBase_C.OverrideConflictingSkins
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, Const)
// Parameters:
// struct FSQItemSkinRestrictionParameters Params_0                                               (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm, NoDestructor)

void UBP_SkinRestrictionsBase_C::OverrideConflictingSkins(const struct FSQItemSkinRestrictionParameters& Params_0) const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_SkinRestrictionsBase_C", "OverrideConflictingSkins");

	Params::BP_SkinRestrictionsBase_C_OverrideConflictingSkins Parms{};

	Parms.Params_0 = std::move(Params_0);

	UObject::ProcessEvent(Func, &Parms);
}

}

