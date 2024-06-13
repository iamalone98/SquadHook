#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: EmoteCenterWidget

#include "Basic.hpp"

#include "EmoteCenterWidget_classes.hpp"
#include "EmoteCenterWidget_parameters.hpp"


namespace SDK
{

// Function EmoteCenterWidget.EmoteCenterWidget_C.ExecuteUbergraph_EmoteCenterWidget
// (Final, UbergraphFunction, HasDefaults)
// Parameters:
// int32                                   EntryPoint                                             (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UEmoteCenterWidget_C::ExecuteUbergraph_EmoteCenterWidget(int32 EntryPoint)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("EmoteCenterWidget_C", "ExecuteUbergraph_EmoteCenterWidget");

	Params::EmoteCenterWidget_C_ExecuteUbergraph_EmoteCenterWidget Parms{};

	Parms.EntryPoint = EntryPoint;

	UObject::ProcessEvent(Func, &Parms);
}


// Function EmoteCenterWidget.EmoteCenterWidget_C.Tick
// (BlueprintCosmetic, Event, Public, BlueprintEvent)
// Parameters:
// struct FGeometry                        MyGeometry                                             (BlueprintVisible, BlueprintReadOnly, Parm, IsPlainOldData, NoDestructor)
// float                                   InDeltaTime                                            (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

void UEmoteCenterWidget_C::Tick(const struct FGeometry& MyGeometry, float InDeltaTime)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("EmoteCenterWidget_C", "Tick");

	Params::EmoteCenterWidget_C_Tick Parms{};

	Parms.MyGeometry = std::move(MyGeometry);
	Parms.InDeltaTime = InDeltaTime;

	UObject::ProcessEvent(Func, &Parms);
}


// Function EmoteCenterWidget.EmoteCenterWidget_C.OnHoverBegin
// (Event, Public, BlueprintCallable, BlueprintEvent)

void UEmoteCenterWidget_C::OnHoverBegin()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("EmoteCenterWidget_C", "OnHoverBegin");

	UObject::ProcessEvent(Func, nullptr);
}


// Function EmoteCenterWidget.EmoteCenterWidget_C.GetCenterText
// (Public, HasOutParams, HasDefaults, BlueprintCallable, BlueprintEvent, BlueprintPure)
// Parameters:
// class FText                             ReturnValue                                            (Parm, OutParm, ReturnParm)

class FText UEmoteCenterWidget_C::GetCenterText()
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("EmoteCenterWidget_C", "GetCenterText");

	Params::EmoteCenterWidget_C_GetCenterText Parms{};

	UObject::ProcessEvent(Func, &Parms);

	return Parms.ReturnValue;
}


// Function EmoteCenterWidget.EmoteCenterWidget_C.GetWidgetText
// (Public, HasOutParams, BlueprintCallable, BlueprintEvent)
// Parameters:
// class USQRadialButton*                  Widget                                                 (BlueprintVisible, BlueprintReadOnly, Parm, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
// class FText                             DisplayText                                            (Parm, OutParm)

void UEmoteCenterWidget_C::GetWidgetText(class USQRadialButton* Widget, class FText* DisplayText)
{
	static class UFunction* Func = nullptr;

	if (Func == nullptr)
		Func = Class->GetFunction("EmoteCenterWidget_C", "GetWidgetText");

	Params::EmoteCenterWidget_C_GetWidgetText Parms{};

	Parms.Widget = Widget;

	UObject::ProcessEvent(Func, &Parms);

	if (DisplayText != nullptr)
		*DisplayText = std::move(Parms.DisplayText);
}

}
