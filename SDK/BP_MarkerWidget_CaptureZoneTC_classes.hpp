#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: BP_MarkerWidget_CaptureZoneTC

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "Squad_classes.hpp"
#include "UMG_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass BP_MarkerWidget_CaptureZoneTC.BP_MarkerWidget_CaptureZoneTC_C
// 0x0130 (0x0488 - 0x0358)
class UBP_MarkerWidget_CaptureZoneTC_C final : public USQMapWidgetCaptureZone
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0358(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       Pulse;                                             // 0x0360(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UImage*                                 Anchor;                                            // 0x0368(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                AnchorBG;                                          // 0x0370(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              AnchorIcon;                                        // 0x0378(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 B;                                                 // 0x0380(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BL;                                                // 0x0388(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 BR;                                                // 0x0390(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCanvasPanel*                           CanvasPanel_Main;                                  // 0x0398(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UProgressBar*                           CaptureBar;                                        // 0x03A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             FlagNameText;                                      // 0x03A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HexFill;                                           // 0x03B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HexHashed;                                         // 0x03B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 HexOutline;                                        // 0x03C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               HexParent;                                         // 0x03C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Protected;                                         // 0x03D0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ProtectIcon;                                       // 0x03D8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleBox_Info;                                     // 0x03E0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_CaptureBar;                                // 0x03E8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class USizeBox*                               SizeBox_Main;                                      // 0x03F0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 T;                                                 // 0x03F8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TL;                                                // 0x0400(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 TR;                                                // 0x0408(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             CloseTooltip;                                      // 0x0410(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	float                                         UpdateStateTime;                                   // 0x0420(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_46FD[0x4];                                     // 0x0424(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class ATC_HexZone_C*                          This_Hex_Zone;                                     // 0x0428(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class ASQPlayerController*                    My_PC;                                             // 0x0430(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	TArray<class UImage*>                         Edge_Lines;                                        // 0x0438(0x0010)(Edit, BlueprintVisible, DisableEditOnInstance, ContainsInstancedReference)
	float                                         Flag_Radius;                                       // 0x0448(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_46FE[0x4];                                     // 0x044C(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class FString                                 Grid_Ref;                                          // 0x0450(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, HasGetValueTypeHash)
	float                                         MaxZoomFactor;                                     // 0x0460(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Zoom_Alpha;                                        // 0x0464(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Show_Large_Text_Threshold;                         // 0x0468(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Show_Data_Threshold;                               // 0x046C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Can_Animate_Capture_Fade;                          // 0x0470(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_46FF[0x7];                                     // 0x0471(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FTimerHandle                           Update_Timer;                                      // 0x0478(0x0008)(Edit, BlueprintVisible, DisableEditOnInstance, NoDestructor, HasGetValueTypeHash)
	bool                                          Is_Point_of_Interest;                              // 0x0480(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_4700[0x3];                                     // 0x0481(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	int32                                         PlayerController_Team_ID;                          // 0x0484(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void CloseTooltip__DelegateSignature();
	void ExecuteUbergraph_BP_MarkerWidget_CaptureZoneTC(int32 EntryPoint);
	void Construct();
	void Stop_Timer_Update_Hex(class UUMG_MenuBase_C* Menu);
	void Start_Timer_Update_Hex(class UUMG_MenuBase_C* Menu);
	void UpdateState();
	void Play_Capture_Fade_Animation();
	void OnCapturePercentChanged();
	void Reset_Hex_Opacity();
	void Destruct();
	void Set_Name_Via_Grid_Ref();
	void OnScaleChanged(float UniformScale);
	void OnFlagNameChanged();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Update_Widget();
	void Update_Hex_Color();
	void Update_Capture_Bar();
	void Get_Same_Team(bool* Same);
	void Can_Cap(class ATC_HexZone_C* Zone, bool Self_Team, bool* Param_Can_Cap);
	void Update_Anchor_Visual();
	void Get_Hex_Zone();
	void Nearby_Zones(bool* Team_1_Nearby, bool* Team_2_Nearby);
	void Update_Frontline();
	void Get_Owner(class ATC_HexZone_C* Zone, bool* Friendly, bool* Enemy, bool* Neutral);
	void Get_Captor(class ATC_HexZone_C* Zone, bool* Friendly, bool* Enemy, bool* Neutral);
	void Get_Can_Cap_Team(class ATC_HexZone_C* Zone, bool* Friendly, bool* Enemy, bool* Neutral);
	void Get_Hex_Owning_Team(uint8* Param_OwningTeam);
	class FText Get_Hex_Text();
	bool Get_POI();
	void Update_Visibility_from_Save_Data();
	void Bind_BPHUD_Events();
	void Update_Touching_Start();
	void Update_Protected_Visibility();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"BP_MarkerWidget_CaptureZoneTC_C">();
	}
	static class UBP_MarkerWidget_CaptureZoneTC_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UBP_MarkerWidget_CaptureZoneTC_C>();
	}
};
static_assert(alignof(UBP_MarkerWidget_CaptureZoneTC_C) == 0x000008, "Wrong alignment on UBP_MarkerWidget_CaptureZoneTC_C");
static_assert(sizeof(UBP_MarkerWidget_CaptureZoneTC_C) == 0x000488, "Wrong size on UBP_MarkerWidget_CaptureZoneTC_C");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, UberGraphFrame) == 0x000358, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Pulse) == 0x000360, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Pulse' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Anchor) == 0x000368, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Anchor' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, AnchorBG) == 0x000370, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::AnchorBG' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, AnchorIcon) == 0x000378, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::AnchorIcon' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, B) == 0x000380, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::B' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, BL) == 0x000388, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::BL' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, BR) == 0x000390, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::BR' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, CanvasPanel_Main) == 0x000398, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::CanvasPanel_Main' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, CaptureBar) == 0x0003A0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::CaptureBar' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, FlagNameText) == 0x0003A8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::FlagNameText' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, HexFill) == 0x0003B0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::HexFill' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, HexHashed) == 0x0003B8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::HexHashed' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, HexOutline) == 0x0003C0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::HexOutline' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, HexParent) == 0x0003C8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::HexParent' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Protected) == 0x0003D0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Protected' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, ProtectIcon) == 0x0003D8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::ProtectIcon' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, ScaleBox_Info) == 0x0003E0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::ScaleBox_Info' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, SizeBox_CaptureBar) == 0x0003E8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::SizeBox_CaptureBar' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, SizeBox_Main) == 0x0003F0, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::SizeBox_Main' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, T) == 0x0003F8, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::T' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, TL) == 0x000400, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::TL' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, TR) == 0x000408, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::TR' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, CloseTooltip) == 0x000410, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::CloseTooltip' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, UpdateStateTime) == 0x000420, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::UpdateStateTime' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, This_Hex_Zone) == 0x000428, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::This_Hex_Zone' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, My_PC) == 0x000430, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::My_PC' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Edge_Lines) == 0x000438, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Edge_Lines' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Flag_Radius) == 0x000448, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Flag_Radius' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Grid_Ref) == 0x000450, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Grid_Ref' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, MaxZoomFactor) == 0x000460, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::MaxZoomFactor' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Zoom_Alpha) == 0x000464, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Zoom_Alpha' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Show_Large_Text_Threshold) == 0x000468, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Show_Large_Text_Threshold' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Show_Data_Threshold) == 0x00046C, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Show_Data_Threshold' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Can_Animate_Capture_Fade) == 0x000470, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Can_Animate_Capture_Fade' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Update_Timer) == 0x000478, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Update_Timer' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, Is_Point_of_Interest) == 0x000480, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::Is_Point_of_Interest' has a wrong offset!");
static_assert(offsetof(UBP_MarkerWidget_CaptureZoneTC_C, PlayerController_Team_ID) == 0x000484, "Member 'UBP_MarkerWidget_CaptureZoneTC_C::PlayerController_Team_ID' has a wrong offset!");

}

