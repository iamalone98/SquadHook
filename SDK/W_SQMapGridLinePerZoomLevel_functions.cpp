#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQMapGridLinePerZoomLevel

#include "Basic.hpp"

#include "W_SQMapGridLinePerZoomLevel_classes.hpp"
#include "W_SQMapGridLinePerZoomLevel_parameters.hpp"


namespace SDK
{

// Function W_SQMapGridLinePerZoomLevel.W_SQMapGridLinePerZoomLevel_C.ExecuteUbergraph_W_SQMapGridLinePerZoomLevel
// (Final, UbergraphFunction)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLinePerZoomLevel_C::ExecuteUbergraph_W_SQMapGridLinePerZoomLevel(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLinePerZoomLevel_C", "ExecuteUbergraph_W_SQMapGridLinePerZoomLevel");

	Params::W_SQMapGridLinePerZoomLevel_C_ExecuteUbergraph_W_SQMapGridLinePerZoomLevel Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapGridLinePerZoomLevel.W_SQMapGridLinePerZoomLevel_C.InitializeTexture
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// class UCurveFloat*                      GridZoomOpacities                                      (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class UTexture2D*                       GridTextures                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   ZoomFadeIn                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   ZoomOpaque                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// int32                                   ScaleFactor                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FLinearColor                     Tint                                                   (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// struct FVector2D                        GridNumbers                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// float                                   StartingZoom                                           (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLinePerZoomLevel_C::InitializeTexture(class UCurveFloat* GridZoomOpacities, class UTexture2D* GridTextures, float ZoomFadeIn, float ZoomOpaque, int32 ScaleFactor, const struct FLinearColor& Tint, const struct FVector2D& GridNumbers, float StartingZoom)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLinePerZoomLevel_C", "InitializeTexture");

	Params::W_SQMapGridLinePerZoomLevel_C_InitializeTexture Parms{};

	Parms.GridZoomOpacities = GridZoomOpacities;
	Parms.GridTextures = GridTextures;
	Parms.ZoomFadeIn = ZoomFadeIn;
	Parms.ZoomOpaque = ZoomOpaque;
	Parms.ScaleFactor = ScaleFactor;
	Parms.Tint = std::move(Tint);
	Parms.GridNumbers = std::move(GridNumbers);
	Parms.StartingZoom = StartingZoom;

	UObject::ProcessEvent(Func, &Parms);
}


// Function W_SQMapGridLinePerZoomLevel.W_SQMapGridLinePerZoomLevel_C.UpdateOpacity
// (BlueprintCallable, BlueprintEvent)
// Parameters:
// float                                   ZoomAmount                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UW_SQMapGridLinePerZoomLevel_C::UpdateOpacity(float ZoomAmount)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("W_SQMapGridLinePerZoomLevel_C", "UpdateOpacity");

	Params::W_SQMapGridLinePerZoomLevel_C_UpdateOpacity Parms{};

	Parms.ZoomAmount = ZoomAmount;

	UObject::ProcessEvent(Func, &Parms);
}

}

