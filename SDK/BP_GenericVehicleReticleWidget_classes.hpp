#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_GenericVehicleReticleWidget

#include "Basic.hpp"

#include "Squad_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_GenericVehicleReticleWidget.BP_GenericVehicleReticleWidget_C
// 0x0000 (0x02A0 - 0x02A0)
class UBP_GenericVehicleReticleWidget_C : public USQVehicleViewWidget
{
public:
	void UpdateTurretHealth();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_GenericVehicleReticleWidget_C">();
	}
	static class UBP_GenericVehicleReticleWidget_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_GenericVehicleReticleWidget_C>();
	}
};
static_assert(alignof(UBP_GenericVehicleReticleWidget_C) == 0x000008, "Wrong alignment on UBP_GenericVehicleReticleWidget_C");
static_assert(sizeof(UBP_GenericVehicleReticleWidget_C) == 0x0002A0, "Wrong size on UBP_GenericVehicleReticleWidget_C");

}
