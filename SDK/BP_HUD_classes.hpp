#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_HUD

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass BP_HUD.BP_HUD_C
// 0x0198 (0x0B08 - 0x0970)
class ABP_HUD_C final : public ASQHUD
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0970(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UUI_Events_Component_C*                 UI_Events_Component;                               // 0x0978(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class USceneComponent*                        DefaultSceneRoot;                                  // 0x0980(0x0008)(BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NonTransactional, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             SquadLeadSymbolTexture;                            // 0x0988(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBaseRadialMenu_C*                      RadialMenu;                                        // 0x0990(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         DamageIndicatorOpacity;                            // 0x0998(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         DamageIndicatorFadeOutTime;                        // 0x099C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          HiddenWidgets;                                     // 0x09A0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_449A[0x7];                                     // 0x09A1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UMainMenuScreen_C*                      MainMenu_Widget;                                   // 0x09A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          bShowingMainMenu;                                  // 0x09B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_449B[0x7];                                     // 0x09B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           ShowMarkerPlacementResetTimer;                     // 0x09B8(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	float                                         NewMarkerShowTime;                                 // 0x09C0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         HudMarkerScaleTime;                                // 0x09C4(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         HudMarkerSolidTime;                                // 0x09C8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_449C[0x4];                                     // 0x09CC(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UUMG_Compass_C*                         CompassWidgetNewUMG;                               // 0x09D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MarkerStartFadeDistance;                           // 0x09D8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MarkerEndFadeDistance;                             // 0x09DC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MarkerScaleSizeMultiplier;                         // 0x09E0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_449D[0x4];                                     // 0x09E4(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	TArray<class UClass*>                         WidgetTypesToHideOnMainMenu;                       // 0x09E8(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance)
	class UUMG_MenuBase_C*                        Deployment;                                        // 0x09F8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_MenuBase_C*                        Command;                                           // 0x0A00(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 SQ_Base_HUD_Class;                                 // 0x0A08(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UUMG_MenuBase_C*                        RoamingMap;                                        // 0x0A10(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          OpenMutex;                                         // 0x0A18(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_449E[0x7];                                     // 0x0A19(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	FMulticastInlineDelegateProperty_             Zoom_Updated;                                      // 0x0A20(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UW_SQMapCore_C*                         MapCore;                                           // 0x0A30(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Command_Widget_Class;                              // 0x0A38(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Deployment_Widget_Class;                           // 0x0A40(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Roaming_Widget_Class;                              // 0x0A48(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 VoteWidgetClass;                                   // 0x0A50(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UUMG_MenuBase_C*>                All_Menus;                                         // 0x0A58(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	class ASQMapMarker*                           Last_HUD_Marker;                                   // 0x0A68(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_WorldMarker_C*                       Last_Widget_Marker;                                // 0x0A70(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Clear_Widgets;                                     // 0x0A78(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class USQNotificationData*                    Notification_Data;                                 // 0x0A88(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 Interact_Widget_Class;                             // 0x0A90(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class USQInteractableWidgetList*              Interact_Widget;                                   // 0x0A98(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UClass*                                 End_Round_Widget_Class;                            // 0x0AA0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Menu_Closed;                                       // 0x0AA8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             Menu_Opened;                                       // 0x0AB8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	FMulticastInlineDelegateProperty_             HUD_Can_Start;                                     // 0x0AC8(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UClass*                                 Default_Voice_Radial;                              // 0x0AD8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             OnMapCoreChanged;                                  // 0x0AE0(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class UUMG_VoteScreen_C*                      VoteScreen;                                        // 0x0AF0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_RadialWheel_C*                       ModularRadialMenu;                                 // 0x0AF8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_PrivacyPolicy_C*                     PrivacyPolicyWidget;                               // 0x0B00(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void Zoom_Updated__DelegateSignature(float Zoom_Amount);
	void Clear_Widgets__DelegateSignature();
	void Menu_Closed__DelegateSignature(class UUMG_MenuBase_C* Menu);
	void Menu_Opened__DelegateSignature(class UUMG_MenuBase_C* Menu);
	void HUD_Can_Start__DelegateSignature();
	void OnMapCoreChanged__DelegateSignature();
	void ExecuteUbergraph_BP_HUD(int32 EntryPoint);
	void DestroyEmoteWheel();
	void CreateEmoteWheel();
	void ReceiveBeginPlay();
	void DeleteMarkerOnHUD();
	void InvalidateMapMarker_Event();
	void CreateMapMarker(const struct FSQMapMarkerVisualData& MapMarkerVisualData);
	void ShowMarkerOnHUD(const struct FSQMapMarkerVisualData& MapMarkerVisualData);
	void Zoom_In_Map_Wheel(float Axis);
	void Zoom_In_Map();
	void Destroy_Radial();
	void Close_Menus();
	void End_Match(int32 Winning_Team, int32 Losing_Team, int32 Winning_Tickets, int32 Loser_Tickets);
	void Game_State_Became_Valid();
	void Player_Died();
	void Menu_Toggle(bool Instant, class UUMG_MenuBase_C* In_Menu, bool Show_Mouse);
	void Toggle_Leaderboard();
	void Show_Leaderboard(bool Show);
	void Close_Radial();
	void Destroy_SL_Menu();
	void Create_SL_Menu();
	void Menu_Close(class UUMG_MenuBase_C* Menu);
	void Toggle_Main_Menu();
	void Clear_All_Floating_Widgets();
	void Show_End_Scoreboard();
	void Create_Radial_Menu(class UClass* Model, class FName Close_Command, class UObject* Context);
	void Show_3D_Marker(class ASQMapMarker* Marker);
	void Open_Voice_Model();
	void Toggle_Scoreboard();
	void Hide_Scoreboard();
	void Show_Scoreboard();
	void Show_End_Round_Widget(int32 Winning_Team, int32 Losing_Team, int32 Winning_Tickets, int32 Losing_Tickets);
	void BPOnUsableVisible(class AActor* Actor, bool bIsVisible);
	void BPOnSetHudWidgetsEnabled(bool bEnabled);
	void ReceiveDestroyed();
	void ReceiveEndPlay(EEndPlayReason EndPlayReason);
	void OnDied();
	void Force_Update_Zoom(float Zoom_Amount);
	void HideAmmoBagOverlay(class ASQDeployableAmmoBag* Ammobag);
	void DisplayAmmoBagOverlay(class ASQDeployableAmmoBag* Ammobag, bool bCanPickup);
	void VehicleCreateOverlay(TSubclassOf<class USQVehicleViewWidget> WidgetClass);
	void HideMarkerPlacement_Event();
	void BlueprintNotifyHit(float DamageTaken, const struct FDamageEvent& DamageEvent, class APawn* PawnInstigator);
	void ReceiveTick(float DeltaSeconds);
	void ReceiveDrawHUD(int32 SizeX, int32 SizeY);
	void Start_Match();
	void Set_Commander_Max_Cooldowns();
	void Open_Deployment();
	void DrawTicketCount(float Size_X);
	void DrawHitIndicator(float Size_X, float Size_Y);
	void CalculateHitIndicatorOpacity(float Delta_Time);
	void DrawHealthIcon(float Size_X, float Size_Y);
	void DrawHUD(int32 Width, int32 Height);
	void Open_Menu(class UUMG_MenuBase_C* Target_Menu, bool Show_Mouse);
	void Close_Menu(class UUMG_MenuBase_C* Target_Menu);
	void ZoomMap();
	void DrawNametag(class APawn* Soldier, const struct FVector2D& Scale, const struct FLinearColor& Color, const struct FVector2D& Location);
	void CreateMainMenu();
	void ShowHideMainMenu();
	void CreateCommandMenu();
	void CreateRadialMenu(class UClass* Model, class FName CloseWindowCommand, class UObject* Context, bool bEditMode, bool bCenterMouse, class UBaseRadialMenu_C** OutputPin);
	void DestroyCommandMenu();
	void DestroyRadialMenu();
	void ToggleMainMenu();
	void GetPlayerStateFromSoldier(class APawn* Pawn, class APlayerState** PlayerState);
	void DrawCurrentMapMarker();
	void CreateScoreboard();
	void CreateChat();
	void Toggle_Menu(bool Instant, class UUMG_MenuBase_C* In_Menu, bool Show_Mouse);
	void Clear_Floating_Widgets();
	void Create_Command();
	void Create_RoamingMap();
	void Close_All_Menus();
	void Remove_SL_Menu();
	void Call_Zoom_Update(float Zoom_Amount);
	void Configure_Map(class UW_SQMapCore_C* Target);
	void Remove_Menus(bool GameEnd);
	void ZoomMapWithWheel(float WheelAxis);
	void Create_Deployment();
	void Show_Spawn_Points();
	void Load_Icon_Scale();
	void Close_Radial_Menu();
	void Draw_Interact_Widget(class AActor* Actor, bool Add);
	void Get_Interactor_Display_Name(class AActor* Actor, class FText* Param_Name);
	void CreateVoiceMenu();
	void Remove_All_Interactable_Widgets();
	void IsGameStateValid(bool* IsValid);
	void CreateVoteScreen();
	void IsEndOfMatch(bool* Out_Is_End_Of_Match);
	void CreateEmoteMenu(class UBaseRadialMenu_C** OutputPin);
	void DestroyEmoteMenu();
	void DisplayPolicy();
	void OnPlayerDataReady(const struct FPlayerData& PlayerData);
	void DisplayAndShowPolicy();
	void Get_Radial_Menu(class UBaseRadialMenu_C** Radial_Menu);
	void Get_Main_Menus(class UUMG_MenuBase_C** Param_Deployment, class UUMG_MenuBase_C** Param_Command, class UUMG_MenuBase_C** Roaming);
	void Get_Is_Showing_Settings_Menu(bool* Showing_Main_Menu);
	void Get_Map_Core(class UW_SQMapCore_C** Map_Core);
	void Get_Map_Component(class USQCoreStateMapComponent** Map_Component);
	void Get_Scoreboard(class USQScoreboard** Param_ScoreBoard);
	void Get_UI_Input_Stacks(TArray<struct FSQInputState>* Input_Stacks);
	void Get_Interactable_Widget(class USQInteractableWidgetList** Param_Interact_Widget);
	void Get_Showing_Main_Menu(bool* Showing);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_HUD_C">();
	}
	static class ABP_HUD_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ABP_HUD_C>();
	}
};
static_assert(alignof(ABP_HUD_C) == 0x000008, "Wrong alignment on ABP_HUD_C");
static_assert(sizeof(ABP_HUD_C) == 0x000B08, "Wrong size on ABP_HUD_C");
static_assert(offsetof(ABP_HUD_C, UberGraphFrame) == 0x000970, "Member 'ABP_HUD_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, UI_Events_Component) == 0x000978, "Member 'ABP_HUD_C::UI_Events_Component' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, DefaultSceneRoot) == 0x000980, "Member 'ABP_HUD_C::DefaultSceneRoot' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, SquadLeadSymbolTexture) == 0x000988, "Member 'ABP_HUD_C::SquadLeadSymbolTexture' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, RadialMenu) == 0x000990, "Member 'ABP_HUD_C::RadialMenu' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, DamageIndicatorOpacity) == 0x000998, "Member 'ABP_HUD_C::DamageIndicatorOpacity' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, DamageIndicatorFadeOutTime) == 0x00099C, "Member 'ABP_HUD_C::DamageIndicatorFadeOutTime' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, HiddenWidgets) == 0x0009A0, "Member 'ABP_HUD_C::HiddenWidgets' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, MainMenu_Widget) == 0x0009A8, "Member 'ABP_HUD_C::MainMenu_Widget' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, bShowingMainMenu) == 0x0009B0, "Member 'ABP_HUD_C::bShowingMainMenu' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, ShowMarkerPlacementResetTimer) == 0x0009B8, "Member 'ABP_HUD_C::ShowMarkerPlacementResetTimer' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, NewMarkerShowTime) == 0x0009C0, "Member 'ABP_HUD_C::NewMarkerShowTime' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, HudMarkerScaleTime) == 0x0009C4, "Member 'ABP_HUD_C::HudMarkerScaleTime' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, HudMarkerSolidTime) == 0x0009C8, "Member 'ABP_HUD_C::HudMarkerSolidTime' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, CompassWidgetNewUMG) == 0x0009D0, "Member 'ABP_HUD_C::CompassWidgetNewUMG' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, MarkerStartFadeDistance) == 0x0009D8, "Member 'ABP_HUD_C::MarkerStartFadeDistance' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, MarkerEndFadeDistance) == 0x0009DC, "Member 'ABP_HUD_C::MarkerEndFadeDistance' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, MarkerScaleSizeMultiplier) == 0x0009E0, "Member 'ABP_HUD_C::MarkerScaleSizeMultiplier' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, WidgetTypesToHideOnMainMenu) == 0x0009E8, "Member 'ABP_HUD_C::WidgetTypesToHideOnMainMenu' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Deployment) == 0x0009F8, "Member 'ABP_HUD_C::Deployment' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Command) == 0x000A00, "Member 'ABP_HUD_C::Command' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, SQ_Base_HUD_Class) == 0x000A08, "Member 'ABP_HUD_C::SQ_Base_HUD_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, RoamingMap) == 0x000A10, "Member 'ABP_HUD_C::RoamingMap' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, OpenMutex) == 0x000A18, "Member 'ABP_HUD_C::OpenMutex' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Zoom_Updated) == 0x000A20, "Member 'ABP_HUD_C::Zoom_Updated' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, MapCore) == 0x000A30, "Member 'ABP_HUD_C::MapCore' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Command_Widget_Class) == 0x000A38, "Member 'ABP_HUD_C::Command_Widget_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Deployment_Widget_Class) == 0x000A40, "Member 'ABP_HUD_C::Deployment_Widget_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Roaming_Widget_Class) == 0x000A48, "Member 'ABP_HUD_C::Roaming_Widget_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, VoteWidgetClass) == 0x000A50, "Member 'ABP_HUD_C::VoteWidgetClass' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, All_Menus) == 0x000A58, "Member 'ABP_HUD_C::All_Menus' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Last_HUD_Marker) == 0x000A68, "Member 'ABP_HUD_C::Last_HUD_Marker' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Last_Widget_Marker) == 0x000A70, "Member 'ABP_HUD_C::Last_Widget_Marker' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Clear_Widgets) == 0x000A78, "Member 'ABP_HUD_C::Clear_Widgets' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Notification_Data) == 0x000A88, "Member 'ABP_HUD_C::Notification_Data' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Interact_Widget_Class) == 0x000A90, "Member 'ABP_HUD_C::Interact_Widget_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Interact_Widget) == 0x000A98, "Member 'ABP_HUD_C::Interact_Widget' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, End_Round_Widget_Class) == 0x000AA0, "Member 'ABP_HUD_C::End_Round_Widget_Class' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Menu_Closed) == 0x000AA8, "Member 'ABP_HUD_C::Menu_Closed' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Menu_Opened) == 0x000AB8, "Member 'ABP_HUD_C::Menu_Opened' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, HUD_Can_Start) == 0x000AC8, "Member 'ABP_HUD_C::HUD_Can_Start' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, Default_Voice_Radial) == 0x000AD8, "Member 'ABP_HUD_C::Default_Voice_Radial' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, OnMapCoreChanged) == 0x000AE0, "Member 'ABP_HUD_C::OnMapCoreChanged' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, VoteScreen) == 0x000AF0, "Member 'ABP_HUD_C::VoteScreen' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, ModularRadialMenu) == 0x000AF8, "Member 'ABP_HUD_C::ModularRadialMenu' has a wrong offset!");
static_assert(offsetof(ABP_HUD_C, PrivacyPolicyWidget) == 0x000B00, "Member 'ABP_HUD_C::PrivacyPolicyWidget' has a wrong offset!");

}
