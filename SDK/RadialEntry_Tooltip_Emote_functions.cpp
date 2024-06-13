#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: RadialEntry_Tooltip_Emote

#include "Basic.hpp"

#include "RadialEntry_Tooltip_Emote_classes.hpp"
#include "RadialEntry_Tooltip_Emote_parameters.hpp"


namespace SDK
{

// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.ExecuteUbergraph_RadialEntry_Tooltip_Emote
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialEntry_Tooltip_Emote_C::ExecuteUbergraph_RadialEntry_Tooltip_Emote(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialEntry_Tooltip_Emote_C", "ExecuteUbergraph_RadialEntry_Tooltip_Emote");

	Params::RadialEntry_Tooltip_Emote_C_ExecuteUbergraph_RadialEntry_Tooltip_Emote Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.OnSetContext
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UBP_RadialItemModel_C*            In_Outer_Context                                       (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialEntry_Tooltip_Emote_C::OnSetContext(class UBP_RadialItemModel_C* In_Outer_Context)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialEntry_Tooltip_Emote_C", "OnSetContext");

	Params::RadialEntry_Tooltip_Emote_C_OnSetContext Parms{};

	Parms.In_Outer_Context = In_Outer_Context;

	UObject::ProcessEvent(Func, &Parms);
}


// Function RadialEntry_Tooltip_Emote.RadialEntry_Tooltip_Emote_C.UpdateDetails
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class FText                             Param_Details                                          (BlueprintVisible, BlueprintReadOnly, Parm)
// class FName                             Key_0                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FName                             Key_1                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FName                             Key_2                                                  (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void URadialEntry_Tooltip_Emote_C::UpdateDetails(const class FText& Param_Details, class FName Key_0, class FName Key_1, class FName Key_2)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("RadialEntry_Tooltip_Emote_C", "UpdateDetails");

	Params::RadialEntry_Tooltip_Emote_C_UpdateDetails Parms{};

	Parms.Param_Details = std::move(Param_Details);
	Parms.Key_0 = Key_0;
	Parms.Key_1 = Key_1;
	Parms.Key_2 = Key_2;

	UObject::ProcessEvent(Func, &Parms);
}

}

