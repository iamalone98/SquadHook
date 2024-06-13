#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_VehicleSpeedo

#include "Basic.hpp"

#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"
#include "ESQVehicleTag_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_VehicleSpeedo.UMG_VehicleSpeedo_C
// 0x01A0 (0x0400 - 0x0260)
class UUMG_VehicleSpeedo_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 AmphibiousImage;                                   // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               AmphibiousIndicator;                               // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Amphibiouis;                                // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Gear;                                       // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Border_Handbrake;                                  // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           DialNumParent;                                     // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 FrontImage;                                        // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               HandBrake;                                         // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HandbrakeImage;                                    // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               PitchParent;                                       // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UHorizontalBox*                         RearmBox;                                          // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 REVs;                                              // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               RollParent;                                        // 0x02D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               SecundaryDisplay;                                  // 0x02D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 SideImage;                                         // 0x02E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 SpeedArrow;                                        // 0x02E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               SpeedParent;                                       // 0x02F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Cost;                                           // 0x02F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Gear;                                           // 0x0300(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class ASQGroundVehicle*                       My_Vehicle;                                        // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         Speed;                                             // 0x0310(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RPM;                                               // 0x0314(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Warning_Roll;                                      // 0x0318(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         Warning_Pitch;                                     // 0x031C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               MI_Revs;                                           // 0x0320(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RevsPercent;                                       // 0x0328(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3838[0x4];                                     // 0x032C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    My_PC;                                             // 0x0330(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerState*                         My_PS;                                             // 0x0338(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             DefaultFrontImage;                                 // 0x0340(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             DefaultSideImage;                                  // 0x0348(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             My_Soldier;                                        // 0x0350(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           Refresh_Timer;                                     // 0x0358(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	struct FSlateColor                            HandbrakeOnColor;                                  // 0x0360(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            HandbrakeOffColor;                                 // 0x0388(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            AmphibiousOnColor;                                 // 0x03B0(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FSlateColor                            AmphibiousOffColor;                                // 0x03D8(0x0028)(Edit, BlueprintVisible, DisableEditOnInstance)

public:
	void ExecuteUbergraph_UMG_VehicleSpeedo(int32 EntryPoint);
	void Validate_Visibility();
	void Soldier_Died();
	void Get_Soldier();
	void Changed_Team(class ASQTeamState* OldTeam, class ASQTeamState* NewTeam);
	void Update_Vehicle(class ASQSoldier* Soldier, class ASQVehicle* Vehicle, class USQVehicleSeatComponent* FromSeat, class USQVehicleSeatComponent* ToSeat);
	void Refresh_Dial();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Construct();
	class FText GearText();
	void Refresh_Widget();
	struct FLinearColor GearColor();
	void DrawDialNumbers();
	void Clear_Dial_Numbers();
	void Update_Revs();
	void Refresh_Icon();
	void Hide_Widget();
	void Rearm_Cost();
	void Refresh_Data();
	void Refresh_Handbrake();
	void Update_Handbrake();
	float GetSpeedometerRange();
	void Refresh_Amphibious_Icon();
	void Update_Amphibious_Icon();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_VehicleSpeedo_C">();
	}
	static class UUMG_VehicleSpeedo_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_VehicleSpeedo_C>();
	}
};
static_assert(alignof(UUMG_VehicleSpeedo_C) == 0x000008, "Wrong alignment on UUMG_VehicleSpeedo_C");
static_assert(sizeof(UUMG_VehicleSpeedo_C) == 0x000400, "Wrong size on UUMG_VehicleSpeedo_C");
static_assert(offsetof(UUMG_VehicleSpeedo_C, UberGraphFrame) == 0x000260, "Member 'UUMG_VehicleSpeedo_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, AmphibiousImage) == 0x000268, "Member 'UUMG_VehicleSpeedo_C::AmphibiousImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, AmphibiousIndicator) == 0x000270, "Member 'UUMG_VehicleSpeedo_C::AmphibiousIndicator' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Border_Amphibiouis) == 0x000278, "Member 'UUMG_VehicleSpeedo_C::Border_Amphibiouis' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Border_Gear) == 0x000280, "Member 'UUMG_VehicleSpeedo_C::Border_Gear' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Border_Handbrake) == 0x000288, "Member 'UUMG_VehicleSpeedo_C::Border_Handbrake' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, DialNumParent) == 0x000290, "Member 'UUMG_VehicleSpeedo_C::DialNumParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, FrontImage) == 0x000298, "Member 'UUMG_VehicleSpeedo_C::FrontImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, HandBrake) == 0x0002A0, "Member 'UUMG_VehicleSpeedo_C::HandBrake' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, HandbrakeImage) == 0x0002A8, "Member 'UUMG_VehicleSpeedo_C::HandbrakeImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Image_0) == 0x0002B0, "Member 'UUMG_VehicleSpeedo_C::Image_0' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, PitchParent) == 0x0002B8, "Member 'UUMG_VehicleSpeedo_C::PitchParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, RearmBox) == 0x0002C0, "Member 'UUMG_VehicleSpeedo_C::RearmBox' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, REVs) == 0x0002C8, "Member 'UUMG_VehicleSpeedo_C::REVs' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, RollParent) == 0x0002D0, "Member 'UUMG_VehicleSpeedo_C::RollParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, SecundaryDisplay) == 0x0002D8, "Member 'UUMG_VehicleSpeedo_C::SecundaryDisplay' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, SideImage) == 0x0002E0, "Member 'UUMG_VehicleSpeedo_C::SideImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, SpeedArrow) == 0x0002E8, "Member 'UUMG_VehicleSpeedo_C::SpeedArrow' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, SpeedParent) == 0x0002F0, "Member 'UUMG_VehicleSpeedo_C::SpeedParent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, TB_Cost) == 0x0002F8, "Member 'UUMG_VehicleSpeedo_C::TB_Cost' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, TB_Gear) == 0x000300, "Member 'UUMG_VehicleSpeedo_C::TB_Gear' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, My_Vehicle) == 0x000308, "Member 'UUMG_VehicleSpeedo_C::My_Vehicle' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Speed) == 0x000310, "Member 'UUMG_VehicleSpeedo_C::Speed' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, RPM) == 0x000314, "Member 'UUMG_VehicleSpeedo_C::RPM' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Warning_Roll) == 0x000318, "Member 'UUMG_VehicleSpeedo_C::Warning_Roll' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Warning_Pitch) == 0x00031C, "Member 'UUMG_VehicleSpeedo_C::Warning_Pitch' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, MI_Revs) == 0x000320, "Member 'UUMG_VehicleSpeedo_C::MI_Revs' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, RevsPercent) == 0x000328, "Member 'UUMG_VehicleSpeedo_C::RevsPercent' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, My_PC) == 0x000330, "Member 'UUMG_VehicleSpeedo_C::My_PC' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, My_PS) == 0x000338, "Member 'UUMG_VehicleSpeedo_C::My_PS' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, DefaultFrontImage) == 0x000340, "Member 'UUMG_VehicleSpeedo_C::DefaultFrontImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, DefaultSideImage) == 0x000348, "Member 'UUMG_VehicleSpeedo_C::DefaultSideImage' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, My_Soldier) == 0x000350, "Member 'UUMG_VehicleSpeedo_C::My_Soldier' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, Refresh_Timer) == 0x000358, "Member 'UUMG_VehicleSpeedo_C::Refresh_Timer' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, HandbrakeOnColor) == 0x000360, "Member 'UUMG_VehicleSpeedo_C::HandbrakeOnColor' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, HandbrakeOffColor) == 0x000388, "Member 'UUMG_VehicleSpeedo_C::HandbrakeOffColor' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, AmphibiousOnColor) == 0x0003B0, "Member 'UUMG_VehicleSpeedo_C::AmphibiousOnColor' has a wrong offset!");
static_assert(offsetof(UUMG_VehicleSpeedo_C, AmphibiousOffColor) == 0x0003D8, "Member 'UUMG_VehicleSpeedo_C::AmphibiousOffColor' has a wrong offset!");

}
