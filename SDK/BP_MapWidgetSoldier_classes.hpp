#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MapWidgetSoldier

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MapWidgetSoldier.BP_MapWidgetSoldier_C
// 0x0178 (0x04C8 - 0x0350)
class UBP_MapWidgetSoldier_C final : public USQMapWidgetSoldier
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0350(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       VoipPulseAnim;                                     // 0x0358(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       SelfPulseAnim;                                     // 0x0360(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       PlayerBleedingAnim;                                // 0x0368(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UWidgetAnimation*                       PlayerIncapAnim;                                   // 0x0370(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Arrow;                                             // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               BleedingPanel;                                     // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BleedingRing;                                      // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DotImage;                                          // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 FireteamDiamondRoles;                              // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 FireteamDot;                                       // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 FTL;                                               // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                IconParent;                                        // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IncapIcon;                                         // 0x03B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               IncapPanel;                                        // 0x03C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IncapRing;                                         // 0x03C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IsCommanderImage;                                  // 0x03D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IsCommanderImageOutline;                           // 0x03D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 IsMedicImage;                                      // 0x03E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Player_Cone_Image;                                 // 0x03E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               PlayerIconSizeBox;                                 // 0x03F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        PlayerIconSwitcher;                                // 0x03F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                PlayerImage;                                       // 0x0400(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                PlayerImageVoip;                                   // 0x0408(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 PulseImage;                                        // 0x0410(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RoleImage;                                         // 0x0418(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RoleImageVoip;                                     // 0x0420(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_0;                                        // 0x0428(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Selection;                                         // 0x0430(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Identifier;                                     // 0x0438(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TooltipHitBox;                                     // 0x0440(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           ViewCone_Rotation;                                 // 0x0448(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               WidgetOverlay;                                     // 0x0450(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	float                                         DefaultScale;                                      // 0x0458(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         MedicScale;                                        // 0x045C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SquadLeaderScale;                                  // 0x0460(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         SelfScale;                                         // 0x0464(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Dir_DefaultImage;                                  // 0x0468(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Dir_SquadLeaderImage;                              // 0x0470(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             Dir_SelfImage;                                     // 0x0478(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UW_Tooltip_Soldier_C*                   REF_Tooltip;                                       // 0x0480(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	int32                                         Pulse_Animation_Loops;                             // 0x0488(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Is_Animating;                                      // 0x048C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_405B[0x3];                                     // 0x048D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerController*                    My_PC;                                             // 0x0490(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Player_Image_Angle_Offset;                         // 0x0498(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Showing_Roles;                                     // 0x049C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_405C[0x3];                                     // 0x049D(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class UTexture2D*                             NonDir_DefaultImage;                               // 0x04A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             NonDir_SquadLeaderImage;                           // 0x04A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UTexture2D*                             NonDir_SelfImage;                                  // 0x04B0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Show_Fireteam_Letters;                             // 0x04B8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_405D[0x7];                                     // 0x04B9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_SQMapCore_C*                         MapCore;                                           // 0x04C0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_BP_MapWidgetSoldier(int32 EntryPoint);
	void OnIsAliveChanged();
	void OnLeaderStateChanged();
	void OnCommanderChangedEvent_Event_0(class ASQPlayerState* OldCommander, class ASQPlayerState* NewCommander);
	void OnIsInSelfTeam();
	void OnIsInSelfSquad();
	void OnAngleChanged();
	void OnFireTeamIndexChanged();
	void OnFireteamIdChanged();
	void OnIsWoundedChanged();
	void OnScaleChanged(float UniformScale);
	void OnCurrentRoleChanged();
	void Construct();
	void OnSelectionStateChanged();
	void OnSoldierInfoChanged();
	void OnCameraRotationYawChanged();
	void OnSquadIdChanged();
	void OnIsInVehicleChanged();
	void OnIsOwnedBySelfChanged();
	void OnIsMedicChanged();
	void OnShowIncapChanged();
	void OnShowBleedingChanged();
	void OnTintValueChanged();
	void Update_Player_Image();
	void Update_Icon_Size();
	class UWidget* Tooltip();
	struct FEventReply On_TooltipHitBox_MouseButtonDown_0(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void Update_Role_Info(float Zoom_Amount);
	void Update_Role_Icon();
	void Same_Fireteam(bool* Same);
	struct FEventReply OnMouseButtonUp(const struct FGeometry& MyGeometry, const struct FPointerEvent& MouseEvent);
	void Update_Is_Medic_Icon();
	void Update_ID();
	void Update_Wounded_Opacity();
	void Update_Color();
	void Update_Tooltip_Color();
	void Set_Show_Fireteam_Letter();
	void Refresh_Element_Visibility();
	void Set_View_Cone_Visibility();
	void UpdateVoipAnim();
	void HandleMapCoreChanged();
	void HandleMapZoom();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MapWidgetSoldier_C">();
	}
	static class UBP_MapWidgetSoldier_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MapWidgetSoldier_C>();
	}
};
static_assert(alignof(UBP_MapWidgetSoldier_C) == 0x000008, "Wrong alignment on UBP_MapWidgetSoldier_C");
static_assert(sizeof(UBP_MapWidgetSoldier_C) == 0x0004C8, "Wrong size on UBP_MapWidgetSoldier_C");
static_assert(offsetof(UBP_MapWidgetSoldier_C, UberGraphFrame) == 0x000350, "Member 'UBP_MapWidgetSoldier_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, VoipPulseAnim) == 0x000358, "Member 'UBP_MapWidgetSoldier_C::VoipPulseAnim' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, SelfPulseAnim) == 0x000360, "Member 'UBP_MapWidgetSoldier_C::SelfPulseAnim' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerBleedingAnim) == 0x000368, "Member 'UBP_MapWidgetSoldier_C::PlayerBleedingAnim' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerIncapAnim) == 0x000370, "Member 'UBP_MapWidgetSoldier_C::PlayerIncapAnim' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Arrow) == 0x000378, "Member 'UBP_MapWidgetSoldier_C::Arrow' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, BleedingPanel) == 0x000380, "Member 'UBP_MapWidgetSoldier_C::BleedingPanel' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, BleedingRing) == 0x000388, "Member 'UBP_MapWidgetSoldier_C::BleedingRing' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, DotImage) == 0x000390, "Member 'UBP_MapWidgetSoldier_C::DotImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, FireteamDiamondRoles) == 0x000398, "Member 'UBP_MapWidgetSoldier_C::FireteamDiamondRoles' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, FireteamDot) == 0x0003A0, "Member 'UBP_MapWidgetSoldier_C::FireteamDot' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, FTL) == 0x0003A8, "Member 'UBP_MapWidgetSoldier_C::FTL' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IconParent) == 0x0003B0, "Member 'UBP_MapWidgetSoldier_C::IconParent' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IncapIcon) == 0x0003B8, "Member 'UBP_MapWidgetSoldier_C::IncapIcon' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IncapPanel) == 0x0003C0, "Member 'UBP_MapWidgetSoldier_C::IncapPanel' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IncapRing) == 0x0003C8, "Member 'UBP_MapWidgetSoldier_C::IncapRing' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IsCommanderImage) == 0x0003D0, "Member 'UBP_MapWidgetSoldier_C::IsCommanderImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IsCommanderImageOutline) == 0x0003D8, "Member 'UBP_MapWidgetSoldier_C::IsCommanderImageOutline' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, IsMedicImage) == 0x0003E0, "Member 'UBP_MapWidgetSoldier_C::IsMedicImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Player_Cone_Image) == 0x0003E8, "Member 'UBP_MapWidgetSoldier_C::Player_Cone_Image' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerIconSizeBox) == 0x0003F0, "Member 'UBP_MapWidgetSoldier_C::PlayerIconSizeBox' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerIconSwitcher) == 0x0003F8, "Member 'UBP_MapWidgetSoldier_C::PlayerIconSwitcher' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerImage) == 0x000400, "Member 'UBP_MapWidgetSoldier_C::PlayerImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PlayerImageVoip) == 0x000408, "Member 'UBP_MapWidgetSoldier_C::PlayerImageVoip' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, PulseImage) == 0x000410, "Member 'UBP_MapWidgetSoldier_C::PulseImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, RoleImage) == 0x000418, "Member 'UBP_MapWidgetSoldier_C::RoleImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, RoleImageVoip) == 0x000420, "Member 'UBP_MapWidgetSoldier_C::RoleImageVoip' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, ScaleBox_0) == 0x000428, "Member 'UBP_MapWidgetSoldier_C::ScaleBox_0' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Selection) == 0x000430, "Member 'UBP_MapWidgetSoldier_C::Selection' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, TB_Identifier) == 0x000438, "Member 'UBP_MapWidgetSoldier_C::TB_Identifier' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, TooltipHitBox) == 0x000440, "Member 'UBP_MapWidgetSoldier_C::TooltipHitBox' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, ViewCone_Rotation) == 0x000448, "Member 'UBP_MapWidgetSoldier_C::ViewCone_Rotation' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, WidgetOverlay) == 0x000450, "Member 'UBP_MapWidgetSoldier_C::WidgetOverlay' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, DefaultScale) == 0x000458, "Member 'UBP_MapWidgetSoldier_C::DefaultScale' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, MedicScale) == 0x00045C, "Member 'UBP_MapWidgetSoldier_C::MedicScale' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, SquadLeaderScale) == 0x000460, "Member 'UBP_MapWidgetSoldier_C::SquadLeaderScale' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, SelfScale) == 0x000464, "Member 'UBP_MapWidgetSoldier_C::SelfScale' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Dir_DefaultImage) == 0x000468, "Member 'UBP_MapWidgetSoldier_C::Dir_DefaultImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Dir_SquadLeaderImage) == 0x000470, "Member 'UBP_MapWidgetSoldier_C::Dir_SquadLeaderImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Dir_SelfImage) == 0x000478, "Member 'UBP_MapWidgetSoldier_C::Dir_SelfImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, REF_Tooltip) == 0x000480, "Member 'UBP_MapWidgetSoldier_C::REF_Tooltip' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Pulse_Animation_Loops) == 0x000488, "Member 'UBP_MapWidgetSoldier_C::Pulse_Animation_Loops' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Is_Animating) == 0x00048C, "Member 'UBP_MapWidgetSoldier_C::Is_Animating' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, My_PC) == 0x000490, "Member 'UBP_MapWidgetSoldier_C::My_PC' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Player_Image_Angle_Offset) == 0x000498, "Member 'UBP_MapWidgetSoldier_C::Player_Image_Angle_Offset' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Showing_Roles) == 0x00049C, "Member 'UBP_MapWidgetSoldier_C::Showing_Roles' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, NonDir_DefaultImage) == 0x0004A0, "Member 'UBP_MapWidgetSoldier_C::NonDir_DefaultImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, NonDir_SquadLeaderImage) == 0x0004A8, "Member 'UBP_MapWidgetSoldier_C::NonDir_SquadLeaderImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, NonDir_SelfImage) == 0x0004B0, "Member 'UBP_MapWidgetSoldier_C::NonDir_SelfImage' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, Show_Fireteam_Letters) == 0x0004B8, "Member 'UBP_MapWidgetSoldier_C::Show_Fireteam_Letters' has a wrong offset!");
static_assert(offsetof(UBP_MapWidgetSoldier_C, MapCore) == 0x0004C0, "Member 'UBP_MapWidgetSoldier_C::MapCore' has a wrong offset!");

}
