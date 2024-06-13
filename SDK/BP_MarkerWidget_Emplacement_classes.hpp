#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_Emplacement

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MarkerWidget_Emplacement.BP_MarkerWidget_Emplacement_C
// 0x0038 (0x02B8 - 0x0280)
class UBP_MarkerWidget_Emplacement_C final : public USQMapIconWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0280(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Vehicle_Image;                                     // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 ViewCone;                                          // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               WidgetOverlay;                                     // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             CloseTooltip;                                      // 0x02A0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UTexture2D*                             VehicleImage;                                      // 0x02B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void CloseTooltip__DelegateSignature();
	void ExecuteUbergraph_BP_MarkerWidget_Emplacement(int32 EntryPoint);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	void SetAngle(float InAngle);
	struct FSlateBrush Get_PlayerImage_Brush();
	void IsOwnOrNeutralTeam(bool* OwnOrNeutral);
	ESlateVisibility Get_Vehicle_Image_Visibility_0();
	void GetVehicleIcon(class UTexture** NewParam);
	void IsNeutralTeam(bool* IsNeutral);
	void IsSameTeam(bool* SameTeam);
	void IsSameSquad(bool* SquadVehicle);
	void GetVehicle(class ASQVehicle** Vehicle);
	void IsVehicleEmpty(bool* Empty);
	ESlateVisibility GetVehicleConeVisbility();
	void IsInVehicle(bool* InVehicle);
	bool IsMarkerVisible();

	void IsSL() const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MarkerWidget_Emplacement_C">();
	}
	static class UBP_MarkerWidget_Emplacement_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MarkerWidget_Emplacement_C>();
	}
};
static_assert(alignof(UBP_MarkerWidget_Emplacement_C) == 0x000008, "Wrong alignment on UBP_MarkerWidget_Emplacement_C");
static_assert(sizeof(UBP_MarkerWidget_Emplacement_C) == 0x0002B8, "Wrong size on UBP_MarkerWidget_Emplacement_C");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, UberGraphFrame) == 0x000280, "Member 'UBP_MarkerWidget_Emplacement_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, Vehicle_Image) == 0x000288, "Member 'UBP_MarkerWidget_Emplacement_C::Vehicle_Image' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, ViewCone) == 0x000290, "Member 'UBP_MarkerWidget_Emplacement_C::ViewCone' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, WidgetOverlay) == 0x000298, "Member 'UBP_MarkerWidget_Emplacement_C::WidgetOverlay' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, CloseTooltip) == 0x0002A0, "Member 'UBP_MarkerWidget_Emplacement_C::CloseTooltip' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_Emplacement_C, VehicleImage) == 0x0002B0, "Member 'UBP_MarkerWidget_Emplacement_C::VehicleImage' has a wrong offset!");

}

