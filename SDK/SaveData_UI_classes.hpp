#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SaveData_UI

#include "Basic.hpp"

#include "E_SortType_structs.hpp"
#include "Engine_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass SaveData_UI.SaveData_UI_C
// 0x0040 (0x0068 - 0x0028)
class USaveData_UI_C final : public USaveGame
{
public:
	bool                                          Show_Map_Roles;                                    // 0x0028(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          SL_Icon_Always_On;                                 // 0x0029(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Stance_Indicator;                             // 0x002A(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_FOB_Radius;                                   // 0x002B(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_FOB_Supplies;                                 // 0x002C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Team_Waypoints;                               // 0x002D(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Grid;                                         // 0x002E(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Spawns;                                       // 0x002F(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Weapons_in_Deployment;                        // 0x0030(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_FT_In_Name_Tag;                               // 0x0031(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DAA[0x2];                                     // 0x0032(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Map_Marker_Scale;                                  // 0x0034(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Lattice_Opacity;                                   // 0x0038(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Grid_Opacity;                                      // 0x003C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          SkipGiveUpOption;                                  // 0x0040(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Fireteam_Letters;                             // 0x0041(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Deployment_Tutorial;                          // 0x0042(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Game_Mode_Animation;                          // 0x0043(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Vehicle_Keybinds;                             // 0x0044(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_TC_Zones;                                     // 0x0045(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Play_Capture_Sounds;                               // 0x0046(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Favourites_Only;                              // 0x0047(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	E_SortType                                    LastSortType;                                      // 0x0048(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          LastAscendingSortType;                             // 0x0049(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          DisableOnScreenChat;                               // 0x004A(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Director_Lines;                               // 0x004B(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_2DAB[0x4];                                     // 0x004C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<TSoftObjectPtr<class USQEmotesData>>   EquippedEmotes;                                    // 0x0050(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	bool                                          Show_Connection_Messages;                          // 0x0060(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bFirstRun;                                         // 0x0061(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"SaveData_UI_C">();
	}
	static class USaveData_UI_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<USaveData_UI_C>();
	}
};
static_assert(alignof(USaveData_UI_C) == 0x000008, "Wrong alignment on USaveData_UI_C");
static_assert(sizeof(USaveData_UI_C) == 0x000068, "Wrong size on USaveData_UI_C");
static_assert(offsetof(USaveData_UI_C, Show_Map_Roles) == 0x000028, "Member 'USaveData_UI_C::Show_Map_Roles' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, SL_Icon_Always_On) == 0x000029, "Member 'USaveData_UI_C::SL_Icon_Always_On' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Stance_Indicator) == 0x00002A, "Member 'USaveData_UI_C::Show_Stance_Indicator' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_FOB_Radius) == 0x00002B, "Member 'USaveData_UI_C::Show_FOB_Radius' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_FOB_Supplies) == 0x00002C, "Member 'USaveData_UI_C::Show_FOB_Supplies' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Team_Waypoints) == 0x00002D, "Member 'USaveData_UI_C::Show_Team_Waypoints' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Grid) == 0x00002E, "Member 'USaveData_UI_C::Show_Grid' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Spawns) == 0x00002F, "Member 'USaveData_UI_C::Show_Spawns' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Weapons_in_Deployment) == 0x000030, "Member 'USaveData_UI_C::Show_Weapons_in_Deployment' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_FT_In_Name_Tag) == 0x000031, "Member 'USaveData_UI_C::Show_FT_In_Name_Tag' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Map_Marker_Scale) == 0x000034, "Member 'USaveData_UI_C::Map_Marker_Scale' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Lattice_Opacity) == 0x000038, "Member 'USaveData_UI_C::Lattice_Opacity' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Grid_Opacity) == 0x00003C, "Member 'USaveData_UI_C::Grid_Opacity' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, SkipGiveUpOption) == 0x000040, "Member 'USaveData_UI_C::SkipGiveUpOption' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Fireteam_Letters) == 0x000041, "Member 'USaveData_UI_C::Show_Fireteam_Letters' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Deployment_Tutorial) == 0x000042, "Member 'USaveData_UI_C::Show_Deployment_Tutorial' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Game_Mode_Animation) == 0x000043, "Member 'USaveData_UI_C::Show_Game_Mode_Animation' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Vehicle_Keybinds) == 0x000044, "Member 'USaveData_UI_C::Show_Vehicle_Keybinds' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_TC_Zones) == 0x000045, "Member 'USaveData_UI_C::Show_TC_Zones' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Play_Capture_Sounds) == 0x000046, "Member 'USaveData_UI_C::Play_Capture_Sounds' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Favourites_Only) == 0x000047, "Member 'USaveData_UI_C::Show_Favourites_Only' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, LastSortType) == 0x000048, "Member 'USaveData_UI_C::LastSortType' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, LastAscendingSortType) == 0x000049, "Member 'USaveData_UI_C::LastAscendingSortType' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, DisableOnScreenChat) == 0x00004A, "Member 'USaveData_UI_C::DisableOnScreenChat' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Director_Lines) == 0x00004B, "Member 'USaveData_UI_C::Show_Director_Lines' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, EquippedEmotes) == 0x000050, "Member 'USaveData_UI_C::EquippedEmotes' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, Show_Connection_Messages) == 0x000060, "Member 'USaveData_UI_C::Show_Connection_Messages' has a wrong offset!");
static_assert(offsetof(USaveData_UI_C, bFirstRun) == 0x000061, "Member 'USaveData_UI_C::bFirstRun' has a wrong offset!");

}

