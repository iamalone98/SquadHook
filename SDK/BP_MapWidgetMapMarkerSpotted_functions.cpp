#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetMapMarkerSpotted

#include "Basic.hpp"

#include "BP_MapWidgetMapMarkerSpotted_classes.hpp"
#include "BP_MapWidgetMapMarkerSpotted_parameters.hpp"


namespace SDK
{

// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.ExecuteUbergraph_BP_MapWidgetMapMarkerSpotted
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetMapMarkerSpotted_C::ExecuteUbergraph_BP_MapWidgetMapMarkerSpotted(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "ExecuteUbergraph_BP_MapWidgetMapMarkerSpotted");

	Params::BP_MapWidgetMapMarkerSpotted_C_ExecuteUbergraph_BP_MapWidgetMapMarkerSpotted Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MapWidgetMapMarkerSpotted_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetMapMarkerSpotted_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "Tick");

	Params::BP_MapWidgetMapMarkerSpotted_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.Destruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UBP_MapWidgetMapMarkerSpotted_C::Destruct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "Destruct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UBP_MapWidgetMapMarkerSpotted_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "OnScaleChanged");

	Params::BP_MapWidgetMapMarkerSpotted_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.OnRightClicked
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetMapMarkerSpotted_C::OnRightClicked()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "OnRightClicked");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.OnTintChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetMapMarkerSpotted_C::OnTintChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "OnTintChanged");

	UObject::ProcessEvent(Func, nullptr);
}


// Function BP_MapWidgetMapMarkerSpotted.BP_MapWidgetMapMarkerSpotted_C.OnTextureChanged
// (Event, Protected, BlueprintEvent)

void UBP_MapWidgetMapMarkerSpotted_C::OnTextureChanged()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("BP_MapWidgetMapMarkerSpotted_C", "OnTextureChanged");

	UObject::ProcessEvent(Func, nullptr);
}

}

