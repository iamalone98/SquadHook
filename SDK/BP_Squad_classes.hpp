#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_Squad

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_Squad.BP_Squad_C
// 0x0008 (0x06D0 - 0x06C8)
class ABP_Squad_C final : public ASQSquad
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x06C8(0x0008)(ZeroConstructor, Transient, DuplicateTransient)

public:
	void ExecuteUbergraph_BP_Squad(int32 EntryPoint);
	void OnPlayerBecomeSquadLeader_Event_0(class ASQSquad* Squad, class ASQPlayerController* Player);
	void OnPlayerJoinSquad_Event_0(class ASQSquad* Squad, class ASQPlayerController* Player);
	void OnPlayerPartSquad_Event_0(class ASQSquad* Squad, class ASQPlayerController* Player);
	void OnFireteamUpdated_Event_0(class ASQSquad* Squad, int32 FireTeamId);
	void ReceiveBeginPlay();
	void OnFireteamDisbanded_Event_0(class ASQSquad* Squad, int32 FireTeamId);
	void ReceiveDestroyed();
	void Destroy_All_Markers();
	void Destroy_Fireteam_Markers(int32 ID);
	void Fireteam_Notification(class ASQSquad* Squad, int32 FT);
	void Parting_Notification(class ASQSquad* Squad, class AController* Leaving_State);
	void Become_SL_Notification(class ASQSquad* State);
	void OnJoinedEvent(class ASQSquad* Squad, class AController* Joining_State);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_Squad_C">();
	}
	static class ABP_Squad_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_Squad_C>();
	}
};
static_assert(alignof(ABP_Squad_C) == 0x000008, "Wrong alignment on ABP_Squad_C");
static_assert(sizeof(ABP_Squad_C) == 0x0006D0, "Wrong size on ABP_Squad_C");
static_assert(offsetof(ABP_Squad_C, UberGraphFrame) == 0x0006C8, "Member 'ABP_Squad_C::UberGraphFrame' has a wrong offset!");

}
