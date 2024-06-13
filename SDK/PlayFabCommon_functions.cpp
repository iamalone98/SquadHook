#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: PlayFabCommon

#include "Basic.hpp"

#include "PlayFabCommon_classes.hpp"
#include "PlayFabCommon_parameters.hpp"


namespace SDK
{

// Function PlayFabCommon.PlayFabAuthenticationContext.ForgetAllCredentials
// (Final, Native, Public, BlueprintCallable)

void UPlayFabAuthenticationContext::ForgetAllCredentials()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "ForgetAllCredentials");

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, nullptr);

	Func->FunctionFlags = Flgs;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.GetClientSessionTicket
// (Final, Native, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// class FString                           ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, HasGetValueTypeHash, NativeAccessSpecifierPublic)

class FString UPlayFabAuthenticationContext::GetClientSessionTicket()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "GetClientSessionTicket");

	Params::PlayFabAuthenticationContext_GetClientSessionTicket Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.GetDeveloperSecretKey
// (Final, Native, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// class FString                           ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, HasGetValueTypeHash, NativeAccessSpecifierPublic)

class FString UPlayFabAuthenticationContext::GetDeveloperSecretKey()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "GetDeveloperSecretKey");

	Params::PlayFabAuthenticationContext_GetDeveloperSecretKey Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.GetEntityToken
// (Final, Native, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// class FString                           ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, HasGetValueTypeHash, NativeAccessSpecifierPublic)

class FString UPlayFabAuthenticationContext::GetEntityToken()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "GetEntityToken");

	Params::PlayFabAuthenticationContext_GetEntityToken Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.GetPlayFabId
// (Final, Native, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// class FString                           ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, HasGetValueTypeHash, NativeAccessSpecifierPublic)

class FString UPlayFabAuthenticationContext::GetPlayFabId()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "GetPlayFabId");

	Params::PlayFabAuthenticationContext_GetPlayFabId Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.SetClientSessionTicket
// (Final, Native, Public, BlueprintCallable)
// Parameters:
// class FString                           InTicket                                               (Parm, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

void UPlayFabAuthenticationContext::SetClientSessionTicket(const class FString& InTicket)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "SetClientSessionTicket");

	Params::PlayFabAuthenticationContext_SetClientSessionTicket Parms{};

	Parms.InTicket = std::move(InTicket);

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.SetDeveloperSecretKey
// (Final, Native, Public, BlueprintCallable)
// Parameters:
// class FString                           InKey                                                  (Parm, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

void UPlayFabAuthenticationContext::SetDeveloperSecretKey(const class FString& InKey)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "SetDeveloperSecretKey");

	Params::PlayFabAuthenticationContext_SetDeveloperSecretKey Parms{};

	Parms.InKey = std::move(InKey);

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.SetEntityToken
// (Final, Native, Public, BlueprintCallable)
// Parameters:
// class FString                           InToken                                                (Parm, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

void UPlayFabAuthenticationContext::SetEntityToken(const class FString& InToken)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "SetEntityToken");

	Params::PlayFabAuthenticationContext_SetEntityToken Parms{};

	Parms.InToken = std::move(InToken);

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.SetPlayFabId
// (Final, Native, Public, BlueprintCallable)
// Parameters:
// class FString                           InKey                                                  (Parm, ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

void UPlayFabAuthenticationContext::SetPlayFabId(const class FString& InKey)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "SetPlayFabId");

	Params::PlayFabAuthenticationContext_SetPlayFabId Parms{};

	Parms.InKey = std::move(InKey);

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;
}


// Function PlayFabCommon.PlayFabAuthenticationContext.ClientAdminSecurityCheck
// (Final, Native, Public, BlueprintCallable, Const)

void UPlayFabAuthenticationContext::ClientAdminSecurityCheck() const
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("PlayFabAuthenticationContext", "ClientAdminSecurityCheck");

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	UObject::ProcessEvent(Func, nullptr);

	Func->FunctionFlags = Flgs;
}

}
