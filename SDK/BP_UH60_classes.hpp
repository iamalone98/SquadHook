#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_UH60

#include "Basic.hpp"

#include "BP_Generic_Helicopter_classes.hpp"
#include "Engine_structs.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_UH60.BP_UH60_C
// 0x0180 (0x0FC0 - 0x0E40)
class ABP_UH60_C final : public ABP_Generic_Helicopter_C
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame_BP_UH60_C;                          // 0x0E40(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint4;                               // 0x0E48(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint9;                               // 0x0E50(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint8;                               // 0x0E58(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint7;                               // 0x0E60(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint6;                               // 0x0E68(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint5;                               // 0x0E70(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Engine_Stats_Plane_2;                              // 0x0E78(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Direction_Plane;                                   // 0x0E80(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Camera_Plane;                                      // 0x0E88(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Engine_Stats_Plane;                                // 0x0E90(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Map_Plane;                                         // 0x0E98(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Compass_Plane;                                     // 0x0EA0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Copilot_Plane;                                     // 0x0EA8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   Main_Plane;                                        // 0x0EB0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint3;                               // 0x0EB8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleExitPointComponent*           SQVehicleExitPoint2;                               // 0x0EC0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   NoPenetationCol;                                   // 0x0EC8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBoxComponent*                          PawnBlockingVolume;                                // 0x0ED0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USQVehicleResourceWeaponInventoryComponent* SQVehicleResourceWeaponInventory;                  // 0x0ED8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   L_GunMount;                                        // 0x0EE0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   R_GunMount;                                        // 0x0EE8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   SupplyCrate2;                                      // 0x0EF0(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UStaticMeshComponent*                   SupplyCrate;                                       // 0x0EF8(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       DirectionScreen;                                   // 0x0F00(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       ForwardCamera;                                     // 0x0F08(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       EngineStats2;                                      // 0x0F10(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPointLightComponent*                   PointLight_0;                                      // 0x0F18(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPointLightComponent*                   PointLight3_0;                                     // 0x0F20(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPointLightComponent*                   PointLight2_0;                                     // 0x0F28(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPointLightComponent*                   PointLight1_0;                                     // 0x0F30(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       EngineStats;                                       // 0x0F38(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       Compass;                                           // 0x0F40(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       MapDisplay;                                        // 0x0F48(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       CopilotDisplay;                                    // 0x0F50(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UWidgetComponent*                       MainDisplay;                                       // 0x0F58(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         Timeline_1_0_LightIntensity_859CD02A453ADBC451100F93F6EE56E8; // 0x0F60(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_1_0__Direction_859CD02A453ADBC451100F93F6EE56E8; // 0x0F64(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4D92[0x3];                                     // 0x0F65(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_1_0;                                      // 0x0F68(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Timeline_0_0_Progress_3BA5EA3845B56EB865203BA049C8B264; // 0x0F70(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	ETimelineDirection                            Timeline_0_0__Direction_3BA5EA3845B56EB865203BA049C8B264; // 0x0F74(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4D93[0x3];                                     // 0x0F75(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTimelineComponent*                     Timeline_0_0;                                      // 0x0F78(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          ReadyToFly;                                        // 0x0F80(0x0001)(Edit, BlueprintVisible, ZeroConstructor, Transient, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4D94[0x7];                                     // 0x0F81(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterialInstanceDynamic*               UH60_Mat;                                          // 0x0F88(0x0008)(Edit, BlueprintVisible, ZeroConstructor, Transient, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ActivationProgress;                                // 0x0F90(0x0004)(Edit, BlueprintVisible, ZeroConstructor, Transient, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_4D95[0x4];                                     // 0x0F94(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           Warning_Light_On_Timer;                            // 0x0F98(0x0008)(Edit, BlueprintVisible, Transient, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          Warning_On_0;                                      // 0x0FA0(0x0001)(Edit, BlueprintVisible, Net, ZeroConstructor, Transient, DisableEditOnInstance, IsPlainOldData, RepNotify, NoDestructor)
	uint8                                         Pad_4D96[0x7];                                     // 0x0FA1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMaterial*                              ScreenMat;                                         // 0x0FA8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          IsCASVariant;                                      // 0x0FB0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_BP_UH60(int32 EntryPoint);
	void Set_UI_Enabled(bool Enable_UI);
	void DeactivationSequence();
	void ActivationSequence();
	void ReceiveBeginPlay();
	void Timeline_1_0__UpdateFunc();
	void Timeline_1_0__FinishedFunc();
	void Timeline_0_0__UpdateFunc();
	void Timeline_0_0__FinishedFunc();
	void UserConstructionScript();
	void Manage_Helicopter_Widgets(bool Enabled);
	void Get_UI_Tint(struct FLinearColor* Color);
	void Set_Helicopter_Widgets_Visibility(ESlateVisibility InVisibility);
	void Set_Helicopter_Widget_Materials(bool* All_Valid_);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_UH60_C">();
	}
	static class ABP_UH60_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_UH60_C>();
	}
};
static_assert(alignof(ABP_UH60_C) == 0x000010, "Wrong alignment on ABP_UH60_C");
static_assert(sizeof(ABP_UH60_C) == 0x000FC0, "Wrong size on ABP_UH60_C");
static_assert(offsetof(ABP_UH60_C, UberGraphFrame_BP_UH60_C) == 0x000E40, "Member 'ABP_UH60_C::UberGraphFrame_BP_UH60_C' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint4) == 0x000E48, "Member 'ABP_UH60_C::SQVehicleExitPoint4' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint9) == 0x000E50, "Member 'ABP_UH60_C::SQVehicleExitPoint9' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint8) == 0x000E58, "Member 'ABP_UH60_C::SQVehicleExitPoint8' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint7) == 0x000E60, "Member 'ABP_UH60_C::SQVehicleExitPoint7' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint6) == 0x000E68, "Member 'ABP_UH60_C::SQVehicleExitPoint6' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint5) == 0x000E70, "Member 'ABP_UH60_C::SQVehicleExitPoint5' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Engine_Stats_Plane_2) == 0x000E78, "Member 'ABP_UH60_C::Engine_Stats_Plane_2' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Direction_Plane) == 0x000E80, "Member 'ABP_UH60_C::Direction_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Camera_Plane) == 0x000E88, "Member 'ABP_UH60_C::Camera_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Engine_Stats_Plane) == 0x000E90, "Member 'ABP_UH60_C::Engine_Stats_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Map_Plane) == 0x000E98, "Member 'ABP_UH60_C::Map_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Compass_Plane) == 0x000EA0, "Member 'ABP_UH60_C::Compass_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Copilot_Plane) == 0x000EA8, "Member 'ABP_UH60_C::Copilot_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Main_Plane) == 0x000EB0, "Member 'ABP_UH60_C::Main_Plane' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint3) == 0x000EB8, "Member 'ABP_UH60_C::SQVehicleExitPoint3' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleExitPoint2) == 0x000EC0, "Member 'ABP_UH60_C::SQVehicleExitPoint2' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, NoPenetationCol) == 0x000EC8, "Member 'ABP_UH60_C::NoPenetationCol' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, PawnBlockingVolume) == 0x000ED0, "Member 'ABP_UH60_C::PawnBlockingVolume' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SQVehicleResourceWeaponInventory) == 0x000ED8, "Member 'ABP_UH60_C::SQVehicleResourceWeaponInventory' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, L_GunMount) == 0x000EE0, "Member 'ABP_UH60_C::L_GunMount' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, R_GunMount) == 0x000EE8, "Member 'ABP_UH60_C::R_GunMount' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SupplyCrate2) == 0x000EF0, "Member 'ABP_UH60_C::SupplyCrate2' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, SupplyCrate) == 0x000EF8, "Member 'ABP_UH60_C::SupplyCrate' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, DirectionScreen) == 0x000F00, "Member 'ABP_UH60_C::DirectionScreen' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, ForwardCamera) == 0x000F08, "Member 'ABP_UH60_C::ForwardCamera' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, EngineStats2) == 0x000F10, "Member 'ABP_UH60_C::EngineStats2' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, PointLight_0) == 0x000F18, "Member 'ABP_UH60_C::PointLight_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, PointLight3_0) == 0x000F20, "Member 'ABP_UH60_C::PointLight3_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, PointLight2_0) == 0x000F28, "Member 'ABP_UH60_C::PointLight2_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, PointLight1_0) == 0x000F30, "Member 'ABP_UH60_C::PointLight1_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, EngineStats) == 0x000F38, "Member 'ABP_UH60_C::EngineStats' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Compass) == 0x000F40, "Member 'ABP_UH60_C::Compass' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, MapDisplay) == 0x000F48, "Member 'ABP_UH60_C::MapDisplay' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, CopilotDisplay) == 0x000F50, "Member 'ABP_UH60_C::CopilotDisplay' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, MainDisplay) == 0x000F58, "Member 'ABP_UH60_C::MainDisplay' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_1_0_LightIntensity_859CD02A453ADBC451100F93F6EE56E8) == 0x000F60, "Member 'ABP_UH60_C::Timeline_1_0_LightIntensity_859CD02A453ADBC451100F93F6EE56E8' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_1_0__Direction_859CD02A453ADBC451100F93F6EE56E8) == 0x000F64, "Member 'ABP_UH60_C::Timeline_1_0__Direction_859CD02A453ADBC451100F93F6EE56E8' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_1_0) == 0x000F68, "Member 'ABP_UH60_C::Timeline_1_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_0_0_Progress_3BA5EA3845B56EB865203BA049C8B264) == 0x000F70, "Member 'ABP_UH60_C::Timeline_0_0_Progress_3BA5EA3845B56EB865203BA049C8B264' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_0_0__Direction_3BA5EA3845B56EB865203BA049C8B264) == 0x000F74, "Member 'ABP_UH60_C::Timeline_0_0__Direction_3BA5EA3845B56EB865203BA049C8B264' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Timeline_0_0) == 0x000F78, "Member 'ABP_UH60_C::Timeline_0_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, ReadyToFly) == 0x000F80, "Member 'ABP_UH60_C::ReadyToFly' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, UH60_Mat) == 0x000F88, "Member 'ABP_UH60_C::UH60_Mat' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, ActivationProgress) == 0x000F90, "Member 'ABP_UH60_C::ActivationProgress' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Warning_Light_On_Timer) == 0x000F98, "Member 'ABP_UH60_C::Warning_Light_On_Timer' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, Warning_On_0) == 0x000FA0, "Member 'ABP_UH60_C::Warning_On_0' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, ScreenMat) == 0x000FA8, "Member 'ABP_UH60_C::ScreenMat' has a wrong offset!");
static_assert(offsetof(ABP_UH60_C, IsCASVariant) == 0x000FB0, "Member 'ABP_UH60_C::IsCASVariant' has a wrong offset!");

}

