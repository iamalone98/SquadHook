#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_Helicopter_MiniMap

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_Helicopter_MiniMap.W_Helicopter_MiniMap_C
// 0x0048 (0x02A8 - 0x0260)
class UW_Helicopter_MiniMap_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       ShowAnim;                                          // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 GPSMap;                                            // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Icon_Player;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UMaterialInstanceDynamic*               MapMaterialInstance;                               // 0x0280(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_SQMapBody_C*                         Map_Body;                                          // 0x0288(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           FadeAnimation;                                     // 0x0290(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          Open;                                              // 0x0298(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Engine_Active;                                     // 0x0299(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4DC0[0x6];                                     // 0x029A(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQHelicopter2*                         Helicopter;                                        // 0x02A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_Helicopter_MiniMap(int32 EntryPoint);
	void Get_World();
	void PlayCloseAnim();
	void FinishOpen();
	void PlayOpenAnim();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void InitializeMap(class ASQHelicopter2* OwningVehicle);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_Helicopter_MiniMap_C">();
	}
	static class UW_Helicopter_MiniMap_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_Helicopter_MiniMap_C>();
	}
};
static_assert(alignof(UW_Helicopter_MiniMap_C) == 0x000008, "Wrong alignment on UW_Helicopter_MiniMap_C");
static_assert(sizeof(UW_Helicopter_MiniMap_C) == 0x0002A8, "Wrong size on UW_Helicopter_MiniMap_C");
static_assert(offsetof(UW_Helicopter_MiniMap_C, UberGraphFrame) == 0x000260, "Member 'UW_Helicopter_MiniMap_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, ShowAnim) == 0x000268, "Member 'UW_Helicopter_MiniMap_C::ShowAnim' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, GPSMap) == 0x000270, "Member 'UW_Helicopter_MiniMap_C::GPSMap' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, Icon_Player) == 0x000278, "Member 'UW_Helicopter_MiniMap_C::Icon_Player' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, MapMaterialInstance) == 0x000280, "Member 'UW_Helicopter_MiniMap_C::MapMaterialInstance' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, Map_Body) == 0x000288, "Member 'UW_Helicopter_MiniMap_C::Map_Body' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, FadeAnimation) == 0x000290, "Member 'UW_Helicopter_MiniMap_C::FadeAnimation' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, Open) == 0x000298, "Member 'UW_Helicopter_MiniMap_C::Open' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, Engine_Active) == 0x000299, "Member 'UW_Helicopter_MiniMap_C::Engine_Active' has a wrong offset!");
static_assert(offsetof(UW_Helicopter_MiniMap_C, Helicopter) == 0x0002A0, "Member 'UW_Helicopter_MiniMap_C::Helicopter' has a wrong offset!");

}

