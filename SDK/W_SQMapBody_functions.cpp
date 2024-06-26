#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQMapBody

#include "Basic.hpp"

#include "W_SQMapBody_classes.hpp"
#include "W_SQMapBody_parameters.hpp"


namespace SDK
{

// Function W_SQMapBody.W_SQMapBody_C.ExecuteUbergraph_W_SQMapBody
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapBody_C::ExecuteUbergraph_W_SQMapBody(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "ExecuteUbergraph_W_SQMapBody");

	Params::W_SQMapBody_C_ExecuteUbergraph_W_SQMapBody Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapBody.W_SQMapBody_C.LoopInitMapBoundary
// (BlueprintCallable, BlueprintEvent)

void UW_SQMapBody_C::LoopInitMapBoundary()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "LoopInitMapBoundary");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SQMapBody.W_SQMapBody_C.Set Flag Lattice Visibility
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    InVisibility                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SQMapBody_C::Set_Flag_Lattice_Visibility(bool InVisibility)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "Set Flag Lattice Visibility");

	Params::W_SQMapBody_C_Set_Flag_Lattice_Visibility Parms{};

	Parms.InVisibility = InVisibility;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapBody.W_SQMapBody_C.InitializeLattice
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQCoreStateMapComponent*         MapComponent                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapBody_C::InitializeLattice(class USQCoreStateMapComponent* MapComponent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "InitializeLattice");

	Params::W_SQMapBody_C_InitializeLattice Parms{};

	Parms.MapComponent = MapComponent;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapBody.W_SQMapBody_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_SQMapBody_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_SQMapBody.W_SQMapBody_C.PreConstruct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// bool                                    IsDesignTime                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SQMapBody_C::PreConstruct(bool IsDesignTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "PreConstruct");

	Params::W_SQMapBody_C_PreConstruct Parms{};

	Parms.IsDesignTime = IsDesignTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapBody.W_SQMapBody_C.CreateMarkerWidget
// (Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FSQMapMarkerVisualData           MapMarkerVisualData                                    (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, NoDestructor)
// class USQMapMarkerBase*                 ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

class USQMapMarkerBase* UW_SQMapBody_C::CreateMarkerWidget(const struct FSQMapMarkerVisualData& MapMarkerVisualData)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "CreateMarkerWidget");

	Params::W_SQMapBody_C_CreateMarkerWidget Parms{};

	Parms.MapMarkerVisualData = std::move(MapMarkerVisualData);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_SQMapBody.W_SQMapBody_C.RemoveMarkerWidget
// (Event, Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQMapMarkerBase*                 Target                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// bool                                    ReturnValue                                            (Parm, OutParm, ZeroConstructor, ReturnParm, IsPlainOldData, NoDestructor)

bool UW_SQMapBody_C::RemoveMarkerWidget(class USQMapMarkerBase* Target)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "RemoveMarkerWidget");

	Params::W_SQMapBody_C_RemoveMarkerWidget Parms{};

	Parms.Target = Target;

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function W_SQMapBody.W_SQMapBody_C.Init Map Boundary
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// bool                                    Success                                                (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor)

void UW_SQMapBody_C::Init_Map_Boundary(bool* Success)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "Init Map Boundary");

	Params::W_SQMapBody_C_Init_Map_Boundary Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Success != nullptr)
		*Success = Parms.Success;
}


// Function W_SQMapBody.W_SQMapBody_C.Map Corner Bounds
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FVector                          Extent                                                 (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapBody_C::Map_Corner_Bounds(struct FVector* Extent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "Map Corner Bounds");

	Params::W_SQMapBody_C_Map_Corner_Bounds Parms{};

	UObject::ProcessEvent(Func, &Parms);

	if (Extent != nullptr)
		*Extent = std::move(Parms.Extent);
}


// Function W_SQMapBody.W_SQMapBody_C.Get Relative Location
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// struct FVector                          In_Location                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FVector2D                        Relative                                               (Parm, OutParm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapBody_C::Get_Relative_Location(const struct FVector& In_Location, struct FVector2D* Relative)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapBody_C", "Get Relative Location");

	Params::W_SQMapBody_C_Get_Relative_Location Parms{};

	Parms.In_Location = std::move(In_Location);

	UObject::ProcessEvent(Func, &Parms);

	if (Relative != nullptr)
		*Relative = std::move(Parms.Relative);
}

}

