#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SQMapGridLinePerZoomLevel

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_SQMapGridLinePerZoomLevel.W_SQMapGridLinePerZoomLevel_C
// 0x0030 (0x0290 - 0x0260)
class UW_SQMapGridLinePerZoomLevel_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 GridLineImage;                                     // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               MaterialInstance;                                  // 0x0270(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UCurveFloat*                            OpacityCurve;                                      // 0x0278(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ScaleAmountStart;                                  // 0x0280(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ScaleAmountEnd;                                    // 0x0284(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ViewableDistance;                                  // 0x0288(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_SQMapGridLinePerZoomLevel(int32 EntryPoint);
	void InitializeTexture(class UCurveFloat* GridZoomOpacities, class UTexture2D* GridTextures, float ZoomFadeIn, float ZoomOpaque, int32 ScaleFactor, const struct FLinearColor& Tint, const struct FVector2D& GridNumbers, float StartingZoom);
	void UpdateOpacity(float ZoomAmount);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_SQMapGridLinePerZoomLevel_C">();
	}
	static class UW_SQMapGridLinePerZoomLevel_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_SQMapGridLinePerZoomLevel_C>();
	}
};
static_assert(alignof(UW_SQMapGridLinePerZoomLevel_C) == 0x000008, "Wrong alignment on UW_SQMapGridLinePerZoomLevel_C");
static_assert(sizeof(UW_SQMapGridLinePerZoomLevel_C) == 0x000290, "Wrong size on UW_SQMapGridLinePerZoomLevel_C");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, UberGraphFrame) == 0x000260, "Member 'UW_SQMapGridLinePerZoomLevel_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, GridLineImage) == 0x000268, "Member 'UW_SQMapGridLinePerZoomLevel_C::GridLineImage' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, MaterialInstance) == 0x000270, "Member 'UW_SQMapGridLinePerZoomLevel_C::MaterialInstance' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, OpacityCurve) == 0x000278, "Member 'UW_SQMapGridLinePerZoomLevel_C::OpacityCurve' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, ScaleAmountStart) == 0x000280, "Member 'UW_SQMapGridLinePerZoomLevel_C::ScaleAmountStart' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, ScaleAmountEnd) == 0x000284, "Member 'UW_SQMapGridLinePerZoomLevel_C::ScaleAmountEnd' has a wrong offset!");
static_assert(offsetof(UW_SQMapGridLinePerZoomLevel_C, ViewableDistance) == 0x000288, "Member 'UW_SQMapGridLinePerZoomLevel_C::ViewableDistance' has a wrong offset!");

}

