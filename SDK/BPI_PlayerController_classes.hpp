#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BPI_PlayerController

#include "Basic.hpp"

#include "CoreUObject_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BPI_PlayerController.BPI_PlayerController_C
// 0x0000 (0x0028 - 0x0028)
class IBPI_PlayerController_C final : public IInterface
{
public:
	void Trace_Marker(const struct FVector& Start, const struct FVector& End, class USQMapMarkerDataAsset* Marker, bool Hotkey, bool Emote, class UClass* MarkerClass);
	void Set_Selected_Marker(class USQMapWidgetMapMarkerSelectable* Marker_Ref);
	void Clear_Selected_Marker();
	void bCan_Place_Marker(bool* Can_Place);
	void bCan_Remove_Marker(bool* Can_Remove);
	void SetAllowAdminCam(bool bAllowAdminCam);
	void Play_Emote(ESQEmotes Emote, class FName Param_Name);
	void Request_Map_Marker(int32 Squad_ID, ESQTeam Team_ID, int32 Fire_Team_ID, const struct FVector_NetQuantize& Location, const struct FVector_NetQuantize& DistanceRotation, class USQMapMarkerDataAsset* Map_Marker_Data);
	void Request_Marker(class UClass* Marker_Class, const struct FVector& Location, int32 Fire_Team_ID, bool Emote);
	void Remove_Map_Marker_New(uint8 MapMarkerID);
	void Request_Director_Marker(class UClass* Director_Marker, const struct FVector& Location, const struct FRotator& Rotation, const struct FVector& Scale, float Distance, int32 Squad_ID);
	void Request_Command_Marker(class UClass* Command_Marker, const struct FTransform& Transform, float Distance);
	void Remove_Selected_Marker();
	void Get_Last_Selected_Marker(class USQMapWidgetMapMarkerSelectable** Marker);
	void Get_Command_Action_Condition(class UClass** Condition_Class);
	void Accept_Deny_Command_Request(class ABP_MapMarker_Command_Request_C* Marker, bool Accepted);
	void Get_Command_Request_Available(bool* Available, float* Remaining_Time);
	void Set_Last_Command_Request_Time();
	void bCanRemoveMapMarkerNew(class UBP_MapMarker_Selectable_C* Map_Marker, bool* Can_Remove);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BPI_PlayerController_C">();
	}
	static class IBPI_PlayerController_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<IBPI_PlayerController_C>();
	}
};
static_assert(alignof(IBPI_PlayerController_C) == 0x000008, "Wrong alignment on IBPI_PlayerController_C");
static_assert(sizeof(IBPI_PlayerController_C) == 0x000028, "Wrong size on IBPI_PlayerController_C");

}

