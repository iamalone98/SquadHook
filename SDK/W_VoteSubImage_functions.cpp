#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_VoteSubImage

#include "Basic.hpp"

#include "W_VoteSubImage_classes.hpp"
#include "W_VoteSubImage_parameters.hpp"


namespace SDK
{

// Function W_VoteSubImage.W_VoteSubImage_C.ExecuteUbergraph_W_VoteSubImage
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_VoteSubImage_C::ExecuteUbergraph_W_VoteSubImage(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_VoteSubImage_C", "ExecuteUbergraph_W_VoteSubImage");

	Params::W_VoteSubImage_C_ExecuteUbergraph_W_VoteSubImage Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_VoteSubImage.W_VoteSubImage_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_VoteSubImage_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_VoteSubImage_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}

}

