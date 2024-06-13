#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Ocean

#include "Basic.hpp"

#include "BP_Ocean_classes.hpp"
#include "BP_Ocean_parameters.hpp"


namespace SDK
{

// Function BP_Ocean.BP_Ocean_C.ExecuteUbergraph_BP_Ocean
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::ExecuteUbergraph_BP_Ocean(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "ExecuteUbergraph_BP_Ocean");

	Params::BP_Ocean_C_ExecuteUbergraph_BP_Ocean Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.UpdateMaskPosSize
// (BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::UpdateMaskPosSize()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "UpdateMaskPosSize");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.Update Ocean Mask
// (BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::Update_Ocean_Mask()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "Update Ocean Mask");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.OnPackedDataUpdated
// (Event, Public, BlueprintEvent)
// Parameters:
// class UTextureRenderTarget2D*           InPackedData                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::OnPackedDataUpdated(class UTextureRenderTarget2D* InPackedData)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "OnPackedDataUpdated");

	Params::BP_Ocean_C_OnPackedDataUpdated Parms{};

	Parms.InPackedData = InPackedData;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.ReceiveEndPlay
// (Event, Protected, BlueprintEvent)
// Parameters:
// EEndPlayReason                          EndPlayReason                                          (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::ReceiveEndPlay(EEndPlayReason EndPlayReason)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "ReceiveEndPlay");

	Params::BP_Ocean_C_ReceiveEndPlay Parms{};

	Parms.EndPlayReason = EndPlayReason;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.Init
// (BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::Init()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "Init");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.OnSettingsChanged
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQGameUserSettings*              UserSettings                                           (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::OnSettingsChanged(const class USQGameUserSettings* UserSettings)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "OnSettingsChanged");

	Params::BP_Ocean_C_OnSettingsChanged Parms{};

	Parms.UserSettings = UserSettings;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.Rebase
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FVector                          OriginLocation                                         (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::Rebase(const struct FVector& OriginLocation)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "Rebase");

	Params::BP_Ocean_C_Rebase Parms{};

	Parms.OriginLocation = std::move(OriginLocation);

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.ReceiveBeginPlay
// (Event, Protected, BlueprintEvent)

void ABP_Ocean_C::ReceiveBeginPlay()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "ReceiveBeginPlay");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.UserConstructionScript
// (Event, Public, BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::UserConstructionScript()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "UserConstructionScript");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.Set MPC Variables
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::Set_MPC_Variables()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "Set MPC Variables");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.GetMaterialFromModes
// (Public, BlueprintCallable, BlueprintEvent)

void ABP_Ocean_C::GetMaterialFromModes()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "GetMaterialFromModes");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_Ocean.BP_Ocean_C.Set MIDs
// (Public, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UMaterialInterface*               OceanSurface                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UMaterialInterface*               Param_WaterLine                                        (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void ABP_Ocean_C::Set_MIDs(class UMaterialInterface* OceanSurface, class UMaterialInterface* Param_WaterLine)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "Set MIDs");

	Params::BP_Ocean_C_Set_MIDs Parms{};

	Parms.OceanSurface = OceanSurface;
	Parms.Param_WaterLine = Param_WaterLine;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_Ocean.BP_Ocean_C.SetFFTs
// (Public, BlueprintCallable, BlueprintEvent)
// Parameters:
// class UMaterialInstanceDynamic*         Target                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    SetupNormal                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void ABP_Ocean_C::SetFFTs(class UMaterialInstanceDynamic* Target, bool SetupNormal)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_Ocean_C", "SetFFTs");

	Params::BP_Ocean_C_SetFFTs Parms{};

	Parms.Target = Target;
	Parms.SetupNormal = SetupNormal;

	UObject::ProcessEvent(Func, &Parms);
}

}
