#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Marker_Request

#include "Basic.hpp"

#include "W_Marker_Request_classes.hpp"
#include "W_Marker_Request_parameters.hpp"


namespace SDK
{

// Function W_Marker_Request.W_Marker_Request_C.ExecuteUbergraph_W_Marker_Request
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Marker_Request_C::ExecuteUbergraph_W_Marker_Request(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "ExecuteUbergraph_W_Marker_Request");

	Params::W_Marker_Request_C_ExecuteUbergraph_W_Marker_Request Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Marker_Request.W_Marker_Request_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Marker_Request_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "Tick");

	Params::W_Marker_Request_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Marker_Request.W_Marker_Request_C.Set Vis to Commander
// (BlueprintCallable, BlueprintEvent)

void UW_Marker_Request_C::Set_Vis_to_Commander()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "Set Vis to Commander");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Marker_Request.W_Marker_Request_C.OnRightClicked
// (Event, Protected, BlueprintEvent)

void UW_Marker_Request_C::OnRightClicked()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "OnRightClicked");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Marker_Request.W_Marker_Request_C.Find Map Icon
// (BlueprintCallable, BlueprintEvent)

void UW_Marker_Request_C::Find_Map_Icon()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "Find Map Icon");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Marker_Request.W_Marker_Request_C.Construct
// (BlueprintCosmetic, Event, Public, BlueprintEvent)

void UW_Marker_Request_C::Construct()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "Construct");

	UObject::ProcessEvent(Func, nullptr);
}


// Function W_Marker_Request.W_Marker_Request_C.OnScaleChanged
// (Event, Public, BlueprintEvent)
// Parameters:
// float                                   UniformScale                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_Marker_Request_C::OnScaleChanged(float UniformScale)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "OnScaleChanged");

	Params::W_Marker_Request_C_OnScaleChanged Parms{};

	Parms.UniformScale = UniformScale;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_Marker_Request.W_Marker_Request_C.OnPreviewMouseButtonDown
// (BlueprintCosmetic, Event, Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// struct FPointerEvent                    MouseEvent                                             (ConstParm, BlueprintVisible, BlueprintReadOnly, Parm, OutParm, ReferenceParm)
// struct FEventReply                      ReturnValue                                            (Parm, OutParm, ReturnParm)

struct FEventReply UW_Marker_Request_C::OnPreviewMouseButtonDown(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_Marker_Request_C", "OnPreviewMouseButtonDown");

	Params::W_Marker_Request_C_OnPreviewMouseButtonDown Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.MouseEvent = std::move(MouseEvent);

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}

}

