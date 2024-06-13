#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_PlayerController

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_PlayerController.BP_PlayerController_C
// 0x0220 (0x0D20 - 0x0B00)
class ABP_PlayerController_C final : public ASQPlayerController
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0B00(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UBP_RotorListener_C*                    BP_RotorListener;                                  // 0x0B08(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UComp_ResourceControl_C*                Comp_ResourceControl;                              // 0x0B10(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPostProcessComponent*                  MapPostProcess;                                    // 0x0B18(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UPostProcessComponent*                  UIBlurPostProcess;                                 // 0x0B20(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	float                                         TraceInterestRadius;                               // 0x0B28(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39D5[0x4];                                     // 0x0B2C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class ASQSoldier*>                     PawnsWithinRadius;                                 // 0x0B30(0x0010)(Edit, BlueprintVisible, DisableEditOnTemplate, DisableEditOnInstance)
	class FName                                   RoleCategory;                                      // 0x0B40(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           InvalidPlacementColor;                             // 0x0B48(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          PawnHidden;                                        // 0x0B58(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39D6[0x7];                                     // 0x0B59(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTransform                             SavedActorTransform;                               // 0x0B60(0x0030)(Edit, BlueprintVisible, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	struct FTimerHandle                           TimerCheckValidGhost;                              // 0x0B90(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	class UPhysicsHandleComponent*                DraggingPhysicsHandle;                             // 0x0B98(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQMapWidgetMapMarkerSelectable*        LastSQMarker;                                      // 0x0BA0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Spot_Markers;                                  // 0x0BA8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Action_Markers;                                // 0x0BAC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_POI_Markers;                                   // 0x0BB0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Fireteam_Markers;                              // 0x0BB4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Request_Markers;                               // 0x0BB8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39D7[0x4];                                     // 0x0BBC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UClass*>                         FireteamMarkers;                                   // 0x0BC0(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	FMulticastInlineDelegateProperty_             Opened_Chat;                                       // 0x0BD0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class ABP_MapMarker_CommandMaster_C*          Last_Command_Request_Marker;                       // 0x0BE0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Command_Spot_Markers;                          // 0x0BE8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Max_Command_Request_Markers;                       // 0x0BEC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class ABP_MapMarker_DirectorMaster_C*> Director_Markers;                                  // 0x0BF0(0x0010)(Edit, BlueprintVisible, DisableEditOnTemplate, DisableEditOnInstance)
	int32                                         Max_Director_Markers;                              // 0x0C00(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_39D8[0x4];                                     // 0x0C04(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Marker_Created;                                    // 0x0C08(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	bool                                          bAllowAdminCam;                                    // 0x0C18(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39D9[0x7];                                     // 0x0C19(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           Out_of_Bounds_Timer;                               // 0x0C20(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Command_Action_Conditions;                         // 0x0C28(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Last_Command_Request_Time;                         // 0x0C30(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Command_Request_Interval;                          // 0x0C34(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_MapMarker_Selectable_C*             SelectedMapMarker;                                 // 0x0C38(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TMap<class UClass*, class USQMapMarkerDataAsset*> SL_TraceMarkerMapping;                             // 0x0C40(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	TMap<class UClass*, class USQMapMarkerDataAsset*> FTL_TraceMarkerMapping;                            // 0x0C90(0x0050)(Edit, BlueprintVisible, DisableEditOnInstance)
	float                                         ThreeDMarkerCooldownSL;                            // 0x0CE0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         ThreeDMarkerCooldownFTL;                           // 0x0CE4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FTimerHandle                           ThreeDMarkerCooldownTimer;                         // 0x0CE8(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          CachedFTLNotification;                             // 0x0CF0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_39DA[0x3];                                     // 0x0CF1(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         CachedFireteamIndexNotification;                   // 0x0CF4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class FText                                   CachedFTLNameNotificaiton;                         // 0x0CF8(0x0018)(Edit, BlueprintVisible, DisableEditOnInstance)
	struct FTimerHandle                           CheckPlayerStateInitializedTimerHandle;            // 0x0D10(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          bHoldingEmoteKey;                                  // 0x0D18(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void Opened_Chat__DelegateSignature(ESQChat Channel);
	void Marker_Created__DelegateSignature(int32 Squad_ID, class ASQMapMarker* Marker);
	void ExecuteUbergraph_BP_PlayerController(int32 EntryPoint);
	void InpAxisEvt_MapZoom_GP_K2Node_InputAxisEvent_0(float AxisValue);
	void OpenEmoteQuickGate();
	void CloseEmoteQuickGate();
	void ServerPickupItem(class AActor* Item_Object);
	void ToggleHighPrecisionBearing(bool NewState);
	void OnPendingDeathChanged(float KillTimestamp, bool bDeathIsPending);
	void OnSquadChanged(class ASQSquadState* NewSquad, class ASQSquadState* OldSquad, class ASQPlayerState* Param_Player);
	void CheckPlayerStateInitialized();
	void ReceiveBeginPlay();
	void FireteamLeaderChanged(const class FText& PlayerName, int32 FireTeamIndex);
	void ClearTimer3DMarkerCooldown();
	void RequiresLeaderKitNotification();
	void JoinedSquadNotification(class ASQPlayerState* Target);
	void PromotedNotification(bool Commander);
	void LeftSquadNotification(class ASQPlayerState* Target);
	void FireteamUpdatedNotification(int32 FireteamNumber, bool IsFTL);
	void Override_Music(TSoftObjectPtr<class USoundBase> In_Music);
	void BP_ExposeUnavailabilityReason(const struct FDataTableRowHandle& InReason);
	void BP_FailPlaceDeployableFromEquippable(class ASQEquipableItem* Equippable);
	void BP_InitializeDeployableFromEquippable(class ASQDeployableItem* DeployableItem, class ASQEquipableItem* Equippable);
	void BlueprintOnMatchStarted();
	void Remove_Map_Marker_New(uint8 MapMarkerID);
	void Set_Last_Command_Request_Time();
	void Server_Accept_Deny_Command(class ABP_MapMarker_Command_Request_C* Marker, bool Accepted);
	void Accept_Deny_Command_Request(class ABP_MapMarker_Command_Request_C* Marker, bool Accepted);
	void Remove_Selected_Marker();
	void Request_Command_Marker(class UClass* Command_Marker, const struct FTransform& Transform, float Distance);
	void Request_Director_Marker(class UClass* Director_Marker, const struct FVector& Location, const struct FRotator& Rotation, const struct FVector& Scale, float Distance, int32 Squad_ID);
	void Request_Marker(class UClass* Marker_Class, const struct FVector& Location, int32 Fire_Team_ID, bool Emote);
	void Request_Map_Marker(int32 Squad_ID, ESQTeam Team_ID, int32 Fire_Team_ID, const struct FVector_NetQuantize& Location, const struct FVector_NetQuantize& DistanceRotation, class USQMapMarkerDataAsset* Map_Marker_Data);
	void OutOfBoundsTimerCheck();
	void OnOutOfMapBoundsChanged(float KillTimestamp, bool bIsOutOfBounds);
	void Play_Emote(ESQEmotes Emote, class FName Param_Name);
	void SetAllowAdminCam(bool Param_bAllowAdminCam);
	void Clear_Selected_Marker();
	void Set_Selected_Marker(class USQMapWidgetMapMarkerSelectable* Marker_Ref);
	void Trace_Marker(const struct FVector& Start, const struct FVector& End, class USQMapMarkerDataAsset* Marker, bool Hotkey, bool Emote, class UClass* MarkerClass);
	void Request_Place_Director_Marker(class UClass* Action, const struct FTransform& T, float Distance, int32 Squad);
	void Request_Place_Command_Map_Marker(class UClass* Action, const struct FTransform& T, float Distance);
	void Client_Notification(const class FText& Text, ESQNotificationTypes Type, class UTexture2D* Custom_Icon);
	void InpAxisKeyEvt_MouseWheelAxis_K2Node_InputAxisKeyEvent_0(float AxisValue);
	void SERVER_Set_Selected_Marker(class USQMapWidgetMapMarkerSelectable* Marker_Ref);
	void BPTraceMarkerLocation(TSubclassOf<class ASQMapMarker> MarkerClass, const struct FVector& Start, const struct FVector& End);
	void RemoveLastSelectedMarker();
	void RequestRemoveMarker(class USQMapItemComponent* MarkerItem);
	void ServerHidePawn();
	void RequestPlaceMarker(class UClass* MarkerClass, const struct FVector& Location, const int32& FireTeamId, bool Emote);
	void ServerEnableCamera();
	void BlueprintPlayerDied();
	void BlueprintPlayerSpawned();
	void StopShowingTMenu();
	void BlueprintOnMatchEnded(int32 WinningTeam, int32 LosingTeam, int32 WinnerTickets, int32 LoserTickets);
	void InpActEvt_ModifyZeroing_K2Node_InputActionEvent_0(const struct FKey& Key);
	void InpActEvt_ModifyZeroing_K2Node_InputActionEvent_1(const struct FKey& Key);
	void InpActEvt_ToggleSquadList_K2Node_InputActionEvent_2(const struct FKey& Key);
	void InpActEvt_ToggleCompassView_K2Node_InputActionEvent_3(const struct FKey& Key);
	void OnLoaded_3D0EA11243E739CDAFB9A48F64F98F7F(class UObject* Loaded);
	void InpActEvt_VehicleToggleCamera_K2Node_InputActionEvent_4(const struct FKey& Key);
	void InpActEvt_Interact_K2Node_InputActionEvent_5(const struct FKey& Key);
	void InpActEvt_ChatToTeam_K2Node_InputActionEvent_6(const struct FKey& Key);
	void InpActEvt_ChatToSquad_K2Node_InputActionEvent_7(const struct FKey& Key);
	void InpActEvt_ChatToAll_K2Node_InputActionEvent_8(const struct FKey& Key);
	void InpActEvt_CommandMap_K2Node_InputActionEvent_9(const struct FKey& Key);
	void InpActEvt_MapZoom_K2Node_InputActionEvent_10(const struct FKey& Key);
	void InpActEvt_CommandMenu_K2Node_InputActionEvent_11(const struct FKey& Key);
	void InpActEvt_CommandMenu_K2Node_InputActionEvent_12(const struct FKey& Key);
	void InpActEvt_Shift_P_K2Node_InputKeyEvent_0(const struct FKey& Key);
	void InpActEvt_ToggleScoreboard_K2Node_InputActionEvent_13(const struct FKey& Key);
	void InpActEvt_Scoreboard_K2Node_InputActionEvent_14(const struct FKey& Key);
	void InpActEvt_Scoreboard_K2Node_InputActionEvent_15(const struct FKey& Key);
	void InpActEvt_Map_K2Node_InputActionEvent_16(const struct FKey& Key);
	void InpActEvt_SpawnMenu_K2Node_InputActionEvent_17(const struct FKey& Key);
	void InpActEvt_InGameMenu_K2Node_InputActionEvent_18(const struct FKey& Key);
	void HideGameMenus();
	void OnRep_Current_Kit();
	bool OnFireWeaponOverride();
	bool OnAltFireWeaponOverride();
	void DeploymentKeyAction();
	void RoamingMapKeyAction();
	void ZoomKeyAction();
	bool IsSoldierInAVehicle();
	void TraceMarkerLocation(class UClass* MarkerClass, const struct FVector& Start, const struct FVector& End, class USQMapMarkerDataAsset* In_Marker, bool Hotkeyed, bool Emote, bool* ValidPosition, bool* StillInCooldown);
	void ManageMarkers(class ASQMapMarker* NewMarker);
	void ClearFiring();
	void Leave_Menu();
	void CommandKeyAction();
	void Can_Remove_Marker();
	void Can_Place_Marker(bool* Valid);
	void MouseWheelZoomMapAction(float MouseWheelAxis);
	void Remove_Fireteam_Markers(bool bAction);
	void Force_Show_Spawns_on_Map();
	void Cancel_Spawn();
	void Try_to_Open_Menu();
	void Remove_Last_Command_Request_Marker();
	void Create_Command_Request(class UClass* Action, const struct FTransform& Transform, float Distance);
	void Create_Director_Marker(class UClass* Action, const struct FTransform& Transform, float Distance, int32 Squad);
	void Get_Deployable(class UClass** Deployable);
	void PossessAdminCam();
	void Set_Out_of_Bounds_Notification(bool Show);
	void HandleFireteamUpdatedNotification(int32 FireTeamIndex, bool IsFTL);
	void Set_Restricted_Team_Zone_Notification(bool Show);
	bool IsAimingDownSights();
	void bCan_Place_Marker(bool* Can_Place);
	void bCan_Remove_Marker(bool* Can_Remove);
	void Get_Last_Selected_Marker(class USQMapWidgetMapMarkerSelectable** Marker);
	void Get_Command_Action_Condition(class UClass** Condition_Class);
	void Get_Command_Request_Available(bool* Available, float* Remaining_Time);
	void bCanRemoveMapMarkerNew(class UBP_MapMarker_Selectable_C* Map_Marker, bool* Can_Remove);

	void CanOpenRadialMenu(bool* Param_CanOpenRadialMenu) const;
	void GetDeployableReference(class USQDeployableSettings* InDeployableSettings, TSoftClassPtr<class UClass>* OutDeployableReference) const;

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_PlayerController_C">();
	}
	static class ABP_PlayerController_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_PlayerController_C>();
	}
};
static_assert(alignof(ABP_PlayerController_C) == 0x000010, "Wrong alignment on ABP_PlayerController_C");
static_assert(sizeof(ABP_PlayerController_C) == 0x000D20, "Wrong size on ABP_PlayerController_C");
static_assert(offsetof(ABP_PlayerController_C, UberGraphFrame) == 0x000B00, "Member 'ABP_PlayerController_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, BP_RotorListener) == 0x000B08, "Member 'ABP_PlayerController_C::BP_RotorListener' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Comp_ResourceControl) == 0x000B10, "Member 'ABP_PlayerController_C::Comp_ResourceControl' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, MapPostProcess) == 0x000B18, "Member 'ABP_PlayerController_C::MapPostProcess' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, UIBlurPostProcess) == 0x000B20, "Member 'ABP_PlayerController_C::UIBlurPostProcess' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, TraceInterestRadius) == 0x000B28, "Member 'ABP_PlayerController_C::TraceInterestRadius' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, PawnsWithinRadius) == 0x000B30, "Member 'ABP_PlayerController_C::PawnsWithinRadius' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, RoleCategory) == 0x000B40, "Member 'ABP_PlayerController_C::RoleCategory' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, InvalidPlacementColor) == 0x000B48, "Member 'ABP_PlayerController_C::InvalidPlacementColor' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, PawnHidden) == 0x000B58, "Member 'ABP_PlayerController_C::PawnHidden' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, SavedActorTransform) == 0x000B60, "Member 'ABP_PlayerController_C::SavedActorTransform' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, TimerCheckValidGhost) == 0x000B90, "Member 'ABP_PlayerController_C::TimerCheckValidGhost' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, DraggingPhysicsHandle) == 0x000B98, "Member 'ABP_PlayerController_C::DraggingPhysicsHandle' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, LastSQMarker) == 0x000BA0, "Member 'ABP_PlayerController_C::LastSQMarker' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Spot_Markers) == 0x000BA8, "Member 'ABP_PlayerController_C::Max_Spot_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Action_Markers) == 0x000BAC, "Member 'ABP_PlayerController_C::Max_Action_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_POI_Markers) == 0x000BB0, "Member 'ABP_PlayerController_C::Max_POI_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Fireteam_Markers) == 0x000BB4, "Member 'ABP_PlayerController_C::Max_Fireteam_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Request_Markers) == 0x000BB8, "Member 'ABP_PlayerController_C::Max_Request_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, FireteamMarkers) == 0x000BC0, "Member 'ABP_PlayerController_C::FireteamMarkers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Opened_Chat) == 0x000BD0, "Member 'ABP_PlayerController_C::Opened_Chat' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Last_Command_Request_Marker) == 0x000BE0, "Member 'ABP_PlayerController_C::Last_Command_Request_Marker' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Command_Spot_Markers) == 0x000BE8, "Member 'ABP_PlayerController_C::Max_Command_Spot_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Command_Request_Markers) == 0x000BEC, "Member 'ABP_PlayerController_C::Max_Command_Request_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Director_Markers) == 0x000BF0, "Member 'ABP_PlayerController_C::Director_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Max_Director_Markers) == 0x000C00, "Member 'ABP_PlayerController_C::Max_Director_Markers' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Marker_Created) == 0x000C08, "Member 'ABP_PlayerController_C::Marker_Created' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, bAllowAdminCam) == 0x000C18, "Member 'ABP_PlayerController_C::bAllowAdminCam' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Out_of_Bounds_Timer) == 0x000C20, "Member 'ABP_PlayerController_C::Out_of_Bounds_Timer' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Command_Action_Conditions) == 0x000C28, "Member 'ABP_PlayerController_C::Command_Action_Conditions' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Last_Command_Request_Time) == 0x000C30, "Member 'ABP_PlayerController_C::Last_Command_Request_Time' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, Command_Request_Interval) == 0x000C34, "Member 'ABP_PlayerController_C::Command_Request_Interval' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, SelectedMapMarker) == 0x000C38, "Member 'ABP_PlayerController_C::SelectedMapMarker' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, SL_TraceMarkerMapping) == 0x000C40, "Member 'ABP_PlayerController_C::SL_TraceMarkerMapping' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, FTL_TraceMarkerMapping) == 0x000C90, "Member 'ABP_PlayerController_C::FTL_TraceMarkerMapping' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, ThreeDMarkerCooldownSL) == 0x000CE0, "Member 'ABP_PlayerController_C::ThreeDMarkerCooldownSL' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, ThreeDMarkerCooldownFTL) == 0x000CE4, "Member 'ABP_PlayerController_C::ThreeDMarkerCooldownFTL' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, ThreeDMarkerCooldownTimer) == 0x000CE8, "Member 'ABP_PlayerController_C::ThreeDMarkerCooldownTimer' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, CachedFTLNotification) == 0x000CF0, "Member 'ABP_PlayerController_C::CachedFTLNotification' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, CachedFireteamIndexNotification) == 0x000CF4, "Member 'ABP_PlayerController_C::CachedFireteamIndexNotification' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, CachedFTLNameNotificaiton) == 0x000CF8, "Member 'ABP_PlayerController_C::CachedFTLNameNotificaiton' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, CheckPlayerStateInitializedTimerHandle) == 0x000D10, "Member 'ABP_PlayerController_C::CheckPlayerStateInitializedTimerHandle' has a wrong offset!");
static_assert(offsetof(ABP_PlayerController_C, bHoldingEmoteKey) == 0x000D18, "Member 'ABP_PlayerController_C::bHoldingEmoteKey' has a wrong offset!");

}
