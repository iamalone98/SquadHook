#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_WeatherSystem

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Engine_classes.hpp"
#include "CoreUObject_structs.hpp"
#include "EN_Weather_structs.hpp"
#include "PhysicsCore_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_WeatherSystem.BP_WeatherSystem_C
// 0x0138 (0x0360 - 0x0228)
class ABP_WeatherSystem_C final : public AActor
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0228(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UAudioComponent*                        WeatherAudio;                                      // 0x0230(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UBillboardComponent*                    WeatherIcon;                                       // 0x0238(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UArrowComponent*                        WindDirection;                                     // 0x0240(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USphereComponent*                       WeatherEffectCoverage;                             // 0x0248(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0250(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	int32                                         AreaRadius;                                        // 0x0258(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_3355[0x4];                                     // 0x025C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UParticleSystem*                        ParticleSystem;                                    // 0x0260(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_3356[0x8];                                     // 0x0268(0x0008)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTransform                             SpawnTransform;                                    // 0x0270(0x0030)(Edit, BlueprintVisible, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	class AActor*                                 LocalPlayer;                                       // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               ParticleSystemRef;                                 // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CameraUpdateFrequency;                             // 0x02B0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          SystemActive;                                      // 0x02B4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	EN_Weather                                    WeatherType;                                       // 0x02B5(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_3357[0x2];                                     // 0x02B6(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	class UParticleSystemComponent*               DistantParticles;                                  // 0x02B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UObject*>                        NegativeAreas;                                     // 0x02C0(0x0010)(Edit, BlueprintVisible, DisableEditOnTemplate, DisableEditOnInstance)
	bool                                          UseArea;                                           // 0x02D0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	EPhysicalSurface                              PreviousMat;                                       // 0x02D1(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomsFloor;                                        // 0x02D2(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomFrontWall;                                     // 0x02D3(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomBackWall;                                      // 0x02D4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomLeftWall;                                      // 0x02D5(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomRightWall;                                     // 0x02D6(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	EPhysicalSurface                              RoomCeiling;                                       // 0x02D7(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         CeilingHeight;                                     // 0x02D8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RoomWidth;                                         // 0x02DC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         RoomLenght;                                        // 0x02E0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          PlayerIsInside;                                    // 0x02E4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3358[0x3];                                     // 0x02E5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UParticleSystem*                        ClearWeather;                                      // 0x02E8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        Sandstorm;                                         // 0x02F0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        LightSnow;                                         // 0x02F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        HeavySnow;                                         // 0x0300(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        LightRain;                                         // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        HeavyRain;                                         // 0x0310(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystemComponent*               WeatherCylinder;                                   // 0x0318(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        Sandstorm_Cylinder;                                // 0x0320(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        LightSnow_Cylinder;                                // 0x0328(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        HeavySnow_Cylinder;                                // 0x0330(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        LightRain_Cylinder;                                // 0x0338(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UParticleSystem*                        HeavyRain_Cylinder;                                // 0x0340(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          UseWeatherCylinder;                                // 0x0348(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	uint8                                         Pad_3359[0x3];                                     // 0x0349(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         ParticleSystemOffset;                              // 0x034C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          GlobalWind;                                        // 0x0350(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_335A[0x3];                                     // 0x0351(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         WindAngle;                                         // 0x0354(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         WindStrength;                                      // 0x0358(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_WeatherSystem(int32 EntryPoint);
	void ReceiveTick(float DeltaSeconds);
	void ReceiveBeginPlay();
	void UpdateWeatherDirection();
	void CheckPlayerProximity();
	void SetEffectLocation();
	void ApplyWeatherToMap();
	void EnterNegativeArea();
	void LeaveNegativeArea();
	void ResetSpawningParticles();
	void CheckRoofMaterial();
	void CheckRoomType();
	void UserConstructionScript();
	void SetRadius();
	void SpawnDistantParticleSystem();
	void WeatherSystemDirection();
	void SpawnParticleSystem();
	void DrawRoom(float* Param_CeilingHeight, float* Param_RoomWidth, float* Param_RoomLenght, EPhysicalSurface* FloorType);
	void SetupWindMaterial();
	void SetupGlobalWind();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_WeatherSystem_C">();
	}
	static class ABP_WeatherSystem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_WeatherSystem_C>();
	}
};
static_assert(alignof(ABP_WeatherSystem_C) == 0x000010, "Wrong alignment on ABP_WeatherSystem_C");
static_assert(sizeof(ABP_WeatherSystem_C) == 0x000360, "Wrong size on ABP_WeatherSystem_C");
static_assert(offsetof(ABP_WeatherSystem_C, UberGraphFrame) == 0x000228, "Member 'ABP_WeatherSystem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WeatherAudio) == 0x000230, "Member 'ABP_WeatherSystem_C::WeatherAudio' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WeatherIcon) == 0x000238, "Member 'ABP_WeatherSystem_C::WeatherIcon' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WindDirection) == 0x000240, "Member 'ABP_WeatherSystem_C::WindDirection' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WeatherEffectCoverage) == 0x000248, "Member 'ABP_WeatherSystem_C::WeatherEffectCoverage' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, DefaultSceneRoot) == 0x000250, "Member 'ABP_WeatherSystem_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, AreaRadius) == 0x000258, "Member 'ABP_WeatherSystem_C::AreaRadius' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, ParticleSystem) == 0x000260, "Member 'ABP_WeatherSystem_C::ParticleSystem' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, SpawnTransform) == 0x000270, "Member 'ABP_WeatherSystem_C::SpawnTransform' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, LocalPlayer) == 0x0002A0, "Member 'ABP_WeatherSystem_C::LocalPlayer' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, ParticleSystemRef) == 0x0002A8, "Member 'ABP_WeatherSystem_C::ParticleSystemRef' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, CameraUpdateFrequency) == 0x0002B0, "Member 'ABP_WeatherSystem_C::CameraUpdateFrequency' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, SystemActive) == 0x0002B4, "Member 'ABP_WeatherSystem_C::SystemActive' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WeatherType) == 0x0002B5, "Member 'ABP_WeatherSystem_C::WeatherType' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, DistantParticles) == 0x0002B8, "Member 'ABP_WeatherSystem_C::DistantParticles' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, NegativeAreas) == 0x0002C0, "Member 'ABP_WeatherSystem_C::NegativeAreas' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, UseArea) == 0x0002D0, "Member 'ABP_WeatherSystem_C::UseArea' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, PreviousMat) == 0x0002D1, "Member 'ABP_WeatherSystem_C::PreviousMat' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomsFloor) == 0x0002D2, "Member 'ABP_WeatherSystem_C::RoomsFloor' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomFrontWall) == 0x0002D3, "Member 'ABP_WeatherSystem_C::RoomFrontWall' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomBackWall) == 0x0002D4, "Member 'ABP_WeatherSystem_C::RoomBackWall' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomLeftWall) == 0x0002D5, "Member 'ABP_WeatherSystem_C::RoomLeftWall' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomRightWall) == 0x0002D6, "Member 'ABP_WeatherSystem_C::RoomRightWall' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomCeiling) == 0x0002D7, "Member 'ABP_WeatherSystem_C::RoomCeiling' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, CeilingHeight) == 0x0002D8, "Member 'ABP_WeatherSystem_C::CeilingHeight' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomWidth) == 0x0002DC, "Member 'ABP_WeatherSystem_C::RoomWidth' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, RoomLenght) == 0x0002E0, "Member 'ABP_WeatherSystem_C::RoomLenght' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, PlayerIsInside) == 0x0002E4, "Member 'ABP_WeatherSystem_C::PlayerIsInside' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, ClearWeather) == 0x0002E8, "Member 'ABP_WeatherSystem_C::ClearWeather' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, Sandstorm) == 0x0002F0, "Member 'ABP_WeatherSystem_C::Sandstorm' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, LightSnow) == 0x0002F8, "Member 'ABP_WeatherSystem_C::LightSnow' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, HeavySnow) == 0x000300, "Member 'ABP_WeatherSystem_C::HeavySnow' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, LightRain) == 0x000308, "Member 'ABP_WeatherSystem_C::LightRain' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, HeavyRain) == 0x000310, "Member 'ABP_WeatherSystem_C::HeavyRain' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WeatherCylinder) == 0x000318, "Member 'ABP_WeatherSystem_C::WeatherCylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, Sandstorm_Cylinder) == 0x000320, "Member 'ABP_WeatherSystem_C::Sandstorm_Cylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, LightSnow_Cylinder) == 0x000328, "Member 'ABP_WeatherSystem_C::LightSnow_Cylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, HeavySnow_Cylinder) == 0x000330, "Member 'ABP_WeatherSystem_C::HeavySnow_Cylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, LightRain_Cylinder) == 0x000338, "Member 'ABP_WeatherSystem_C::LightRain_Cylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, HeavyRain_Cylinder) == 0x000340, "Member 'ABP_WeatherSystem_C::HeavyRain_Cylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, UseWeatherCylinder) == 0x000348, "Member 'ABP_WeatherSystem_C::UseWeatherCylinder' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, ParticleSystemOffset) == 0x00034C, "Member 'ABP_WeatherSystem_C::ParticleSystemOffset' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, GlobalWind) == 0x000350, "Member 'ABP_WeatherSystem_C::GlobalWind' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WindAngle) == 0x000354, "Member 'ABP_WeatherSystem_C::WindAngle' has a wrong offset!");
static_assert(offsetof(ABP_WeatherSystem_C, WindStrength) == 0x000358, "Member 'ABP_WeatherSystem_C::WindStrength' has a wrong offset!");

}

