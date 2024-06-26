#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_HelicopterDirection

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_HelicopterDirection.W_HelicopterDirection_C
// 0x0028 (0x0288 - 0x0260)
class UW_HelicopterDirection_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UImage*                                 Dot;                                               // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Grid;                                              // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	TScriptInterface<class ISQHelicopterInstruments> VehicleRef;                                        // 0x0278(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_W_HelicopterDirection(int32 EntryPoint);
	void InitializeScreen(TScriptInterface<class ISQHelicopterInstruments> Vehicle);
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_HelicopterDirection_C">();
	}
	static class UW_HelicopterDirection_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_HelicopterDirection_C>();
	}
};
static_assert(alignof(UW_HelicopterDirection_C) == 0x000008, "Wrong alignment on UW_HelicopterDirection_C");
static_assert(sizeof(UW_HelicopterDirection_C) == 0x000288, "Wrong size on UW_HelicopterDirection_C");
static_assert(offsetof(UW_HelicopterDirection_C, UberGraphFrame) == 0x000260, "Member 'UW_HelicopterDirection_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_HelicopterDirection_C, Dot) == 0x000268, "Member 'UW_HelicopterDirection_C::Dot' has a wrong offset!");
static_assert(offsetof(UW_HelicopterDirection_C, Grid) == 0x000270, "Member 'UW_HelicopterDirection_C::Grid' has a wrong offset!");
static_assert(offsetof(UW_HelicopterDirection_C, VehicleRef) == 0x000278, "Member 'UW_HelicopterDirection_C::VehicleRef' has a wrong offset!");

}

