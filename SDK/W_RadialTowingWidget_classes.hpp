#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_RadialTowingWidget

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_RadialTowingWidget.W_RadialTowingWidget_C
// 0x0088 (0x03B8 - 0x0330)
class UW_RadialTowingWidget_C final : public USQRadialButton
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0330(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Background;                                        // 0x0338(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon;                                              // 0x0340(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Iconbackground;                                    // 0x0348(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Move;                                              // 0x0350(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             Subtitle;                                          // 0x0358(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UW_RadialTimer_C*                       Timer;                                             // 0x0360(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         YawWaitDurationFactor;                             // 0x0368(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         JumpWaitDuration;                                  // 0x036C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          EmergencyJump;                                     // 0x0370(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_36CE[0x3];                                     // 0x0371(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         EmergencyYaw;                                      // 0x0374(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQSoldier*                             LocalSoldier;                                      // 0x0378(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQVehicle*                             CurrentVehicle;                                    // 0x0380(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      BaseRadialMenu;                                    // 0x0388(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_RadialItemModel_C*                  RelatedActionModel;                                // 0x0390(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    PlayerController;                                  // 0x0398(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ESQVehicleRecoveryMethod                      Recovery_Method;                                   // 0x03A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_36CF[0x3];                                     // 0x03A1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Push_Wait_Duration_Factor;                         // 0x03A4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ConsecutiveWaitDurationFactor;                     // 0x03A8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ConsecutiveRecoveryTimeLimit;                      // 0x03AC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ConsecutiveDurationFactorDefault;                  // 0x03B0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ConsecutiveDurationFactorQuick;                    // 0x03B4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_RadialTowingWidget(int32 EntryPoint);
	void Construct();
	void ToggleEmergencyJump();
	void AddEmergencyYaw(float Degrees);
	void OnTimerReached();
	void OnHoverEnd();
	void OnHoverBegin();
	void ComputeEmergencyYaw(float Degress);
	void CollectVehicleReference(bool* Success);
	void CollectSoldierReference(bool* Success);
	void IsTeleportationValid(bool* IsValid);
	void SetupWaitDuration();
	void UpdateText();
	void UpdateCentralButton();
	bool Is_Recovery_Method_Valid(class ASQVehicle* Vehicle, ESQVehicleRecoveryMethod Method);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_RadialTowingWidget_C">();
	}
	static class UW_RadialTowingWidget_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_RadialTowingWidget_C>();
	}
};
static_assert(alignof(UW_RadialTowingWidget_C) == 0x000008, "Wrong alignment on UW_RadialTowingWidget_C");
static_assert(sizeof(UW_RadialTowingWidget_C) == 0x0003B8, "Wrong size on UW_RadialTowingWidget_C");
static_assert(offsetof(UW_RadialTowingWidget_C, UberGraphFrame) == 0x000330, "Member 'UW_RadialTowingWidget_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Background) == 0x000338, "Member 'UW_RadialTowingWidget_C::Background' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Icon) == 0x000340, "Member 'UW_RadialTowingWidget_C::Icon' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Iconbackground) == 0x000348, "Member 'UW_RadialTowingWidget_C::Iconbackground' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Move) == 0x000350, "Member 'UW_RadialTowingWidget_C::Move' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Subtitle) == 0x000358, "Member 'UW_RadialTowingWidget_C::Subtitle' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Timer) == 0x000360, "Member 'UW_RadialTowingWidget_C::Timer' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, YawWaitDurationFactor) == 0x000368, "Member 'UW_RadialTowingWidget_C::YawWaitDurationFactor' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, JumpWaitDuration) == 0x00036C, "Member 'UW_RadialTowingWidget_C::JumpWaitDuration' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, EmergencyJump) == 0x000370, "Member 'UW_RadialTowingWidget_C::EmergencyJump' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, EmergencyYaw) == 0x000374, "Member 'UW_RadialTowingWidget_C::EmergencyYaw' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, LocalSoldier) == 0x000378, "Member 'UW_RadialTowingWidget_C::LocalSoldier' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, CurrentVehicle) == 0x000380, "Member 'UW_RadialTowingWidget_C::CurrentVehicle' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, BaseRadialMenu) == 0x000388, "Member 'UW_RadialTowingWidget_C::BaseRadialMenu' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, RelatedActionModel) == 0x000390, "Member 'UW_RadialTowingWidget_C::RelatedActionModel' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, PlayerController) == 0x000398, "Member 'UW_RadialTowingWidget_C::PlayerController' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Recovery_Method) == 0x0003A0, "Member 'UW_RadialTowingWidget_C::Recovery_Method' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, Push_Wait_Duration_Factor) == 0x0003A4, "Member 'UW_RadialTowingWidget_C::Push_Wait_Duration_Factor' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, ConsecutiveWaitDurationFactor) == 0x0003A8, "Member 'UW_RadialTowingWidget_C::ConsecutiveWaitDurationFactor' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, ConsecutiveRecoveryTimeLimit) == 0x0003AC, "Member 'UW_RadialTowingWidget_C::ConsecutiveRecoveryTimeLimit' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, ConsecutiveDurationFactorDefault) == 0x0003B0, "Member 'UW_RadialTowingWidget_C::ConsecutiveDurationFactorDefault' has a wrong offset!");
static_assert(offsetof(UW_RadialTowingWidget_C, ConsecutiveDurationFactorQuick) == 0x0003B4, "Member 'UW_RadialTowingWidget_C::ConsecutiveDurationFactorQuick' has a wrong offset!");

}

