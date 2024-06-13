#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: XeSSBlueprint

#include "Basic.hpp"

#include "XeSSBlueprint_classes.hpp"
#include "XeSSBlueprint_parameters.hpp"


namespace SDK
{

// Function XeSSBlueprint.XeSSBlueprintLibrary.GetDefaultXeSSQualityMode
// (Final, RequiredAPI, Native, Static, Public, HasDefaults, BlueprintCallable, BlueprintPure)
// Parameters:
// struct FIntPoint                        ScreenResolution                                       (Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
// EXeSSQualityMode                        ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

EXeSSQualityMode UXeSSBlueprintLibrary::GetDefaultXeSSQualityMode(const struct FIntPoint& ScreenResolution)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "GetDefaultXeSSQualityMode");

	Params::XeSSBlueprintLibrary_GetDefaultXeSSQualityMode Parms{};

	Parms.ScreenResolution = std::move(ScreenResolution);

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function XeSSBlueprint.XeSSBlueprintLibrary.GetSupportedXeSSQualityModes
// (Final, RequiredAPI, Native, Static, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// TArray<EXeSSQualityMode>                ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, NativeAccessSpecifierPublic)

TArray<EXeSSQualityMode> UXeSSBlueprintLibrary::GetSupportedXeSSQualityModes()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "GetSupportedXeSSQualityModes");

	Params::XeSSBlueprintLibrary_GetSupportedXeSSQualityModes Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function XeSSBlueprint.XeSSBlueprintLibrary.GetXeSSQualityMode
// (Final, RequiredAPI, Native, Static, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// EXeSSQualityMode                        ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

EXeSSQualityMode UXeSSBlueprintLibrary::GetXeSSQualityMode()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "GetXeSSQualityMode");

	Params::XeSSBlueprintLibrary_GetXeSSQualityMode Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function XeSSBlueprint.XeSSBlueprintLibrary.GetXeSSQualityModeInformation
// (Final, RequiredAPI, Native, Static, Public, HasOutParams, BlueprintCallable)
// Parameters:
// EXeSSQualityMode                        QualityMode                                            (Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
// float                                   ScreenPercentage                                       (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

bool UXeSSBlueprintLibrary::GetXeSSQualityModeInformation(EXeSSQualityMode QualityMode, float* ScreenPercentage)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "GetXeSSQualityModeInformation");

	Params::XeSSBlueprintLibrary_GetXeSSQualityModeInformation Parms{};

	Parms.QualityMode = QualityMode;

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	if (ScreenPercentage != nullptr)
		*ScreenPercentage = Parms.ScreenPercentage;

	return Parms.ReturnValue;
}


// Function XeSSBlueprint.XeSSBlueprintLibrary.IsXeSSSupported
// (Final, RequiredAPI, Native, Static, Public, BlueprintCallable, BlueprintPure)
// Parameters:
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

bool UXeSSBlueprintLibrary::IsXeSSSupported()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "IsXeSSSupported");

	Params::XeSSBlueprintLibrary_IsXeSSSupported Parms{};

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;

	return Parms.ReturnValue;
}


// Function XeSSBlueprint.XeSSBlueprintLibrary.SetXeSSQualityMode
// (Final, RequiredAPI, Native, Static, Public, BlueprintCallable)
// Parameters:
// EXeSSQualityMode                        QualityMode                                            (Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)

void UXeSSBlueprintLibrary::SetXeSSQualityMode(EXeSSQualityMode QualityMode)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = StaticClass()->GetFunction("XeSSBlueprintLibrary", "SetXeSSQualityMode");

	Params::XeSSBlueprintLibrary_SetXeSSQualityMode Parms{};

	Parms.QualityMode = QualityMode;

	auto Flgs = Func->FunctionFlags;
	Func->FunctionFlags |= 0x400;

	GetDefaultObj()->ProcessEvent(Func, &Parms);

	Func->FunctionFlags = Flgs;
}

}

