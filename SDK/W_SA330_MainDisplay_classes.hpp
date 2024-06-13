#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_SA330_MainDisplay

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_SA330_MainDisplay.W_SA330_MainDisplay_C
// 0x0138 (0x0398 - 0x0260)
class UW_SA330_MainDisplay_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       DeactivateSequence;                                // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       ActivationSequence;                                // 0x0270(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UTextBlock*                             AltitudeText;                                      // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                BootScreen;                                        // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CompassCentre;                                     // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 CompassCircle;                                     // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Disabledmask;                                      // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           Horizon;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HorizonBG;                                         // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HorizonElementLeft;                                // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HorizonElementRight;                               // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HorizonMask;                                       // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image;                                             // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_1;                                           // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_104;                                         // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_206;                                         // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             KNOTSHSPEED;                                       // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Pitch;                                             // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Pitch20Plus;                                       // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Pitch50minus;                                      // 0x0308(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Pitch50plus;                                       // 0x0310(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             PitchValue;                                        // 0x0318(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Roll;                                              // 0x0320(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RollStatic;                                        // 0x0328(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             RollValue;                                         // 0x0330(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RPM_Gauge;                                         // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TAXI_Indicator;                                    // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_77;                                      // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TextBlock_79;                                      // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UProgressBar*                           Throttle;                                          // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             ThrottlePercent;                                   // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_HelicopterInputDisplay_C*            W_HelicopterInputDisplay_39;                       // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_SA330DisplayDecor_C*                 W_SA330DisplayDecor;                               // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ABP_Generic_Helicopter_C*               OwningVehicle;                                     // 0x0378(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RPMTarget;                                         // 0x0380(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ScreenEnabled;                                     // 0x0384(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DA9[0x3];                                     // 0x0385(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Current_Knot_Speed;                                // 0x0388(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4DAA[0x4];                                     // 0x038C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           Refresh;                                           // 0x0390(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_SA330_MainDisplay(int32 EntryPoint);
	void Manage_Update(bool Can_Update);
	void Screen_Off();
	void Screen_On();
	void Update_RPM();
	void Update_MainDisplay();
	void Update_TAXI();
	void Refresh_HelicopterDisplay();
	void Set_Owning_Vehicle(class ABP_Generic_Helicopter_C* Param_OwningVehicle);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_SA330_MainDisplay_C">();
	}
	static class UW_SA330_MainDisplay_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_SA330_MainDisplay_C>();
	}
};
static_assert(alignof(UW_SA330_MainDisplay_C) == 0x000008, "Wrong alignment on UW_SA330_MainDisplay_C");
static_assert(sizeof(UW_SA330_MainDisplay_C) == 0x000398, "Wrong size on UW_SA330_MainDisplay_C");
static_assert(offsetof(UW_SA330_MainDisplay_C, UberGraphFrame) == 0x000260, "Member 'UW_SA330_MainDisplay_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, DeactivateSequence) == 0x000268, "Member 'UW_SA330_MainDisplay_C::DeactivateSequence' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, ActivationSequence) == 0x000270, "Member 'UW_SA330_MainDisplay_C::ActivationSequence' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, AltitudeText) == 0x000278, "Member 'UW_SA330_MainDisplay_C::AltitudeText' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, BootScreen) == 0x000280, "Member 'UW_SA330_MainDisplay_C::BootScreen' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, CompassCentre) == 0x000288, "Member 'UW_SA330_MainDisplay_C::CompassCentre' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, CompassCircle) == 0x000290, "Member 'UW_SA330_MainDisplay_C::CompassCircle' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Disabledmask) == 0x000298, "Member 'UW_SA330_MainDisplay_C::Disabledmask' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Horizon) == 0x0002A0, "Member 'UW_SA330_MainDisplay_C::Horizon' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, HorizonBG) == 0x0002A8, "Member 'UW_SA330_MainDisplay_C::HorizonBG' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, HorizonElementLeft) == 0x0002B0, "Member 'UW_SA330_MainDisplay_C::HorizonElementLeft' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, HorizonElementRight) == 0x0002B8, "Member 'UW_SA330_MainDisplay_C::HorizonElementRight' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, HorizonMask) == 0x0002C0, "Member 'UW_SA330_MainDisplay_C::HorizonMask' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Image) == 0x0002C8, "Member 'UW_SA330_MainDisplay_C::Image' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Image_0) == 0x0002D0, "Member 'UW_SA330_MainDisplay_C::Image_0' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Image_1) == 0x0002D8, "Member 'UW_SA330_MainDisplay_C::Image_1' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Image_104) == 0x0002E0, "Member 'UW_SA330_MainDisplay_C::Image_104' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Image_206) == 0x0002E8, "Member 'UW_SA330_MainDisplay_C::Image_206' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, KNOTSHSPEED) == 0x0002F0, "Member 'UW_SA330_MainDisplay_C::KNOTSHSPEED' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Pitch) == 0x0002F8, "Member 'UW_SA330_MainDisplay_C::Pitch' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Pitch20Plus) == 0x000300, "Member 'UW_SA330_MainDisplay_C::Pitch20Plus' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Pitch50minus) == 0x000308, "Member 'UW_SA330_MainDisplay_C::Pitch50minus' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Pitch50plus) == 0x000310, "Member 'UW_SA330_MainDisplay_C::Pitch50plus' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, PitchValue) == 0x000318, "Member 'UW_SA330_MainDisplay_C::PitchValue' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Roll) == 0x000320, "Member 'UW_SA330_MainDisplay_C::Roll' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, RollStatic) == 0x000328, "Member 'UW_SA330_MainDisplay_C::RollStatic' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, RollValue) == 0x000330, "Member 'UW_SA330_MainDisplay_C::RollValue' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, RPM_Gauge) == 0x000338, "Member 'UW_SA330_MainDisplay_C::RPM_Gauge' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, TAXI_Indicator) == 0x000340, "Member 'UW_SA330_MainDisplay_C::TAXI_Indicator' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, TextBlock_77) == 0x000348, "Member 'UW_SA330_MainDisplay_C::TextBlock_77' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, TextBlock_79) == 0x000350, "Member 'UW_SA330_MainDisplay_C::TextBlock_79' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Throttle) == 0x000358, "Member 'UW_SA330_MainDisplay_C::Throttle' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, ThrottlePercent) == 0x000360, "Member 'UW_SA330_MainDisplay_C::ThrottlePercent' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, W_HelicopterInputDisplay_39) == 0x000368, "Member 'UW_SA330_MainDisplay_C::W_HelicopterInputDisplay_39' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, W_SA330DisplayDecor) == 0x000370, "Member 'UW_SA330_MainDisplay_C::W_SA330DisplayDecor' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, OwningVehicle) == 0x000378, "Member 'UW_SA330_MainDisplay_C::OwningVehicle' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, RPMTarget) == 0x000380, "Member 'UW_SA330_MainDisplay_C::RPMTarget' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, ScreenEnabled) == 0x000384, "Member 'UW_SA330_MainDisplay_C::ScreenEnabled' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Current_Knot_Speed) == 0x000388, "Member 'UW_SA330_MainDisplay_C::Current_Knot_Speed' has a wrong offset!");
static_assert(offsetof(UW_SA330_MainDisplay_C, Refresh) == 0x000390, "Member 'UW_SA330_MainDisplay_C::Refresh' has a wrong offset!");

}
