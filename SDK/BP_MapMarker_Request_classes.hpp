#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapMarker_Request

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "BP_MapMarker_Selectable_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MapMarker_Request.BP_MapMarker_Request_C
// 0x0020 (0x0378 - 0x0358)
class UBP_MapMarker_Request_C final : public UBP_MapMarker_Selectable_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0358(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       POIin;                                             // 0x0360(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_1;                                        // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MapMarker_Request(int32 EntryPoint);
	void OnHasFadedChanged();
	void OnScaleChanged(float ScaleValue);
	void Construct();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapMarker_Request_C">();
	}
	static class UBP_MapMarker_Request_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MapMarker_Request_C>();
	}
};
static_assert(alignof(UBP_MapMarker_Request_C) == 0x000008, "Wrong alignment on UBP_MapMarker_Request_C");
static_assert(sizeof(UBP_MapMarker_Request_C) == 0x000378, "Wrong size on UBP_MapMarker_Request_C");
static_assert(offsetof(UBP_MapMarker_Request_C, UberGraphFrame) == 0x000358, "Member 'UBP_MapMarker_Request_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MapMarker_Request_C, POIin) == 0x000360, "Member 'UBP_MapMarker_Request_C::POIin' has a wrong offset!");
static_assert(offsetof(UBP_MapMarker_Request_C, Image_0) == 0x000368, "Member 'UBP_MapMarker_Request_C::Image_0' has a wrong offset!");
static_assert(offsetof(UBP_MapMarker_Request_C, ScaleBox_1) == 0x000370, "Member 'UBP_MapMarker_Request_C::ScaleBox_1' has a wrong offset!");

}
