#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG_NameTag

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "NametagTargetInfo_structs.hpp"
#include "UMG_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass UMG_NameTag.UMG_NameTag_C
// 0x0150 (0x03B0 - 0x0260)
class UUMG_NameTag_C : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       FadeIn;                                            // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UTextBlock*                             FTID;                                              // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_2;                                           // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Kit_Image;                                         // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                OpacityBorder_Info;                                // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                OpacityBorder_Rank;                                // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 RankImage;                                         // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UVerticalBox*                           RootBox;                                           // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UScaleBox*                              ScaleKit;                                          // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SQID;                                              // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             SquadID_Top;                                       // 0x02B8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Name;                                           // 0x02C0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_Rank;                               // 0x02C8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	bool                                          Can_Render;                                        // 0x02D0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_390B[0x7];                                     // 0x02D1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class ASQPlayerState*                         REF_Owning_Player_State;                           // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class APlayerCameraManager*                   REF_CameraManager;                                 // 0x02E0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Current_Rank_Opacity;                              // 0x02E8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Current_Info_Opacity;                              // 0x02EC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Smooth_Screen_Position_Speed;                      // 0x02F0(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Is_My_Squad_Leader_Tag;                            // 0x02F4(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	uint8                                         Pad_390C[0x3];                                     // 0x02F5(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Scale;                                             // 0x02F8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Max_Opacity;                                       // 0x02FC(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Show_Kit;                                          // 0x0300(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Show_Name;                                         // 0x0301(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_390D[0x6];                                     // 0x0302(0x0006)(Fixing Size After Last Property [ Dumper-7 ])
	class APawn*                                  Focussed_Pawn;                                     // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	float                                         Z_Offset_Standing;                                 // 0x0310(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Z_Offset_Crouching;                                // 0x0314(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Z_Offset_Prone;                                    // 0x0318(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FVector2D                              Desired_Screen_Location;                           // 0x031C(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	uint8                                         Pad_390E[0x4];                                     // 0x0324(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class UCanvasPanelSlot*                       My_Canvas_Slot;                                    // 0x0328(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Z_Offset_Vehicle;                                  // 0x0330(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Close_Range_for_Close_Angle___cm_;                 // 0x0334(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Far_Range_for_Far_Angle__cm_;                      // 0x0338(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Required_Close_Angle__0Minus1_;                    // 0x033C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Required_Far_Angle__0Minus0_9999_;                 // 0x0340(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Maximum_Range_Whole__cm_;                          // 0x0344(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Minimum_Fade_Range_My_SL__cm_;                     // 0x0348(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Maximum_Fade_Range_My_SL__cm_;                     // 0x034C(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          In_Threshold;                                      // 0x0350(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_390F[0x7];                                     // 0x0351(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	struct FNametagTargetInfo                     CachedTargetInfo;                                  // 0x0358(0x0038)(Edit, BlueprintVisible, DisableEditOnInstance, HasGetValueTypeHash)
	bool                                          Save_Data_SL_Visible;                              // 0x0390(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Save_Data_FT_Visible;                              // 0x0391(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3910[0x2];                                     // 0x0392(0x0002)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         Maximum_Range_Info__cm_;                           // 0x0394(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         Current_Focus_Strength;                            // 0x0398(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          FTLeader;                                          // 0x039C(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          IsMyFTLLeader;                                     // 0x039D(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn)
	bool                                          AlwaysShowFTL;                                     // 0x039E(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          Has_Line_of_Sight;                                 // 0x039F(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor)
	class USQPipScopeCaptureComponent*            Cached_Pip_Component;                              // 0x03A0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, InstancedReference, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	float                                         PIPInsideScopeAlpha;                               // 0x03A8(0x0004)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_UMG_NameTag(int32 EntryPoint);
	void Update_LoS();
	void RefreshTagEvent();
	void FindTargetEvent();
	void Looping_Refresh();
	void Construct();
	void Timer_Check_Threshold();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Get_Local_State();
	void Load_Saved_Settings(const class USQGameUserSettings* UserSettings);
	struct FLinearColor Get_Color();
	void Update_Opacity();
	void Find_Target();
	void Get_ADS(bool* In_ADS);
	struct FSlateBrush Get_Kit_Image();
	void Get_Tag_Test_Location(class APawn* Pawn, struct FVector* Location);
	void Calc_Target_Info(bool* Success, class ASQSquadState** SquadState, class ASQPlayerState** SQ_Player_State, class FText* PlayerName, bool* SL, bool* Same_Squad, int32* Vehicle_Occupants, bool* SameFTL);
	struct FLinearColor GetContentColor_TOP();
	struct FLinearColor GetContentColor_BOTTOM();
	void Get_SL_In_Vehicle(class ASQVehicle* V, class ASQPlayerState** SL);
	void Refresh_Tag();
	void Cache_Data();
	void Update_SL_Save_Data();
	void Update_FT_Save_Data();
	void FindBestTarget();
	void GetScreenLocation(struct FVector& Loc, struct FVector2D* NewParam);
	void DotProductToCam(struct FVector& VecIn, float* Dot);
	void Get_PIP(class USQPipScopeCaptureComponent** PiPComponent);
	void Update_Line_of_Sight();
	void LoS_Trace_Check(const struct FVector& From, bool* Has_LoS);
	void GetTargetDistance(class APawn* Pawn, float* Distance);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"UMG_NameTag_C">();
	}
	static class UUMG_NameTag_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UUMG_NameTag_C>();
	}
};
static_assert(alignof(UUMG_NameTag_C) == 0x000008, "Wrong alignment on UUMG_NameTag_C");
static_assert(sizeof(UUMG_NameTag_C) == 0x0003B0, "Wrong size on UUMG_NameTag_C");
static_assert(offsetof(UUMG_NameTag_C, UberGraphFrame) == 0x000260, "Member 'UUMG_NameTag_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, FadeIn) == 0x000268, "Member 'UUMG_NameTag_C::FadeIn' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, FTID) == 0x000270, "Member 'UUMG_NameTag_C::FTID' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Image_2) == 0x000278, "Member 'UUMG_NameTag_C::Image_2' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Kit_Image) == 0x000280, "Member 'UUMG_NameTag_C::Kit_Image' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, OpacityBorder_Info) == 0x000288, "Member 'UUMG_NameTag_C::OpacityBorder_Info' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, OpacityBorder_Rank) == 0x000290, "Member 'UUMG_NameTag_C::OpacityBorder_Rank' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, RankImage) == 0x000298, "Member 'UUMG_NameTag_C::RankImage' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, RootBox) == 0x0002A0, "Member 'UUMG_NameTag_C::RootBox' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, ScaleKit) == 0x0002A8, "Member 'UUMG_NameTag_C::ScaleKit' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, SQID) == 0x0002B0, "Member 'UUMG_NameTag_C::SQID' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, SquadID_Top) == 0x0002B8, "Member 'UUMG_NameTag_C::SquadID_Top' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, TB_Name) == 0x0002C0, "Member 'UUMG_NameTag_C::TB_Name' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, WidgetSwitcher_Rank) == 0x0002C8, "Member 'UUMG_NameTag_C::WidgetSwitcher_Rank' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Can_Render) == 0x0002D0, "Member 'UUMG_NameTag_C::Can_Render' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, REF_Owning_Player_State) == 0x0002D8, "Member 'UUMG_NameTag_C::REF_Owning_Player_State' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, REF_CameraManager) == 0x0002E0, "Member 'UUMG_NameTag_C::REF_CameraManager' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Current_Rank_Opacity) == 0x0002E8, "Member 'UUMG_NameTag_C::Current_Rank_Opacity' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Current_Info_Opacity) == 0x0002EC, "Member 'UUMG_NameTag_C::Current_Info_Opacity' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Smooth_Screen_Position_Speed) == 0x0002F0, "Member 'UUMG_NameTag_C::Smooth_Screen_Position_Speed' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Is_My_Squad_Leader_Tag) == 0x0002F4, "Member 'UUMG_NameTag_C::Is_My_Squad_Leader_Tag' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Scale) == 0x0002F8, "Member 'UUMG_NameTag_C::Scale' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Max_Opacity) == 0x0002FC, "Member 'UUMG_NameTag_C::Max_Opacity' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Show_Kit) == 0x000300, "Member 'UUMG_NameTag_C::Show_Kit' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Show_Name) == 0x000301, "Member 'UUMG_NameTag_C::Show_Name' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Focussed_Pawn) == 0x000308, "Member 'UUMG_NameTag_C::Focussed_Pawn' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Z_Offset_Standing) == 0x000310, "Member 'UUMG_NameTag_C::Z_Offset_Standing' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Z_Offset_Crouching) == 0x000314, "Member 'UUMG_NameTag_C::Z_Offset_Crouching' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Z_Offset_Prone) == 0x000318, "Member 'UUMG_NameTag_C::Z_Offset_Prone' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Desired_Screen_Location) == 0x00031C, "Member 'UUMG_NameTag_C::Desired_Screen_Location' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, My_Canvas_Slot) == 0x000328, "Member 'UUMG_NameTag_C::My_Canvas_Slot' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Z_Offset_Vehicle) == 0x000330, "Member 'UUMG_NameTag_C::Z_Offset_Vehicle' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Close_Range_for_Close_Angle___cm_) == 0x000334, "Member 'UUMG_NameTag_C::Close_Range_for_Close_Angle___cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Far_Range_for_Far_Angle__cm_) == 0x000338, "Member 'UUMG_NameTag_C::Far_Range_for_Far_Angle__cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Required_Close_Angle__0Minus1_) == 0x00033C, "Member 'UUMG_NameTag_C::Required_Close_Angle__0Minus1_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Required_Far_Angle__0Minus0_9999_) == 0x000340, "Member 'UUMG_NameTag_C::Required_Far_Angle__0Minus0_9999_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Maximum_Range_Whole__cm_) == 0x000344, "Member 'UUMG_NameTag_C::Maximum_Range_Whole__cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Minimum_Fade_Range_My_SL__cm_) == 0x000348, "Member 'UUMG_NameTag_C::Minimum_Fade_Range_My_SL__cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Maximum_Fade_Range_My_SL__cm_) == 0x00034C, "Member 'UUMG_NameTag_C::Maximum_Fade_Range_My_SL__cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, In_Threshold) == 0x000350, "Member 'UUMG_NameTag_C::In_Threshold' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, CachedTargetInfo) == 0x000358, "Member 'UUMG_NameTag_C::CachedTargetInfo' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Save_Data_SL_Visible) == 0x000390, "Member 'UUMG_NameTag_C::Save_Data_SL_Visible' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Save_Data_FT_Visible) == 0x000391, "Member 'UUMG_NameTag_C::Save_Data_FT_Visible' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Maximum_Range_Info__cm_) == 0x000394, "Member 'UUMG_NameTag_C::Maximum_Range_Info__cm_' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Current_Focus_Strength) == 0x000398, "Member 'UUMG_NameTag_C::Current_Focus_Strength' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, FTLeader) == 0x00039C, "Member 'UUMG_NameTag_C::FTLeader' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, IsMyFTLLeader) == 0x00039D, "Member 'UUMG_NameTag_C::IsMyFTLLeader' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, AlwaysShowFTL) == 0x00039E, "Member 'UUMG_NameTag_C::AlwaysShowFTL' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Has_Line_of_Sight) == 0x00039F, "Member 'UUMG_NameTag_C::Has_Line_of_Sight' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, Cached_Pip_Component) == 0x0003A0, "Member 'UUMG_NameTag_C::Cached_Pip_Component' has a wrong offset!");
static_assert(offsetof(UUMG_NameTag_C, PIPInsideScopeAlpha) == 0x0003A8, "Member 'UUMG_NameTag_C::PIPInsideScopeAlpha' has a wrong offset!");

}

