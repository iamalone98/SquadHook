#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_CamControlButton

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_CamControlButton.W_CamControlButton_C
// 0x0088 (0x02E8 - 0x0260)
class UW_CamControlButton_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UButton*                                Button_Main;                                       // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DroneImage;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 DroneTimer;                                        // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_DroneState;                                     // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_Timer;                                          // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTexture2D*                             Drone_Texture;                                     // 0x0290(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	FMulticastInlineDelegateProperty_             Cam_State_Changed;                                 // 0x0298(0x0010)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, BlueprintAssignable, BlueprintCallable)
	class ABP_ControlledCamera_C*                 Camera;                                            // 0x02A8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	bool                                          Cam_Active;                                        // 0x02B0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A3[0x7];                                     // 0x02B1(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UClass*                                 Action;                                            // 0x02B8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	class ASQPlayerController*                    SQ_PC;                                             // 0x02C0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Force_Allowed;                                     // 0x02C8(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_40A4[0x7];                                     // 0x02C9(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class AWorldSettings*                         WorldSettings;                                     // 0x02D0(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnTemplate, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	class UBP_CommanderActionCondition_C*         Command_Condition;                                 // 0x02D8(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          Can_Toggle_Camera;                                 // 0x02E0(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void Cam_State_Changed__DelegateSignature(bool Active, class ABP_ControlledCamera_C* Cam);
	void ExecuteUbergraph_W_CamControlButton(int32 EntryPoint);
	void Fail_Message();
	void PreConstruct(bool IsDesignTime);
	void Remove_Camera_Button();
	void Construct();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void BndEvt__Button_Main_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	void Update_Remote_Camera_Button();
	void Can_Use_Button(bool* Valid);
	class UWidget* Get_Tooltip();
	void Validate_Vehicle_Action(bool* Allowed);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_CamControlButton_C">();
	}
	static class UW_CamControlButton_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_CamControlButton_C>();
	}
};
static_assert(alignof(UW_CamControlButton_C) == 0x000008, "Wrong alignment on UW_CamControlButton_C");
static_assert(sizeof(UW_CamControlButton_C) == 0x0002E8, "Wrong size on UW_CamControlButton_C");
static_assert(offsetof(UW_CamControlButton_C, UberGraphFrame) == 0x000260, "Member 'UW_CamControlButton_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Button_Main) == 0x000268, "Member 'UW_CamControlButton_C::Button_Main' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, DroneImage) == 0x000270, "Member 'UW_CamControlButton_C::DroneImage' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, DroneTimer) == 0x000278, "Member 'UW_CamControlButton_C::DroneTimer' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, TB_DroneState) == 0x000280, "Member 'UW_CamControlButton_C::TB_DroneState' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, TB_Timer) == 0x000288, "Member 'UW_CamControlButton_C::TB_Timer' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Drone_Texture) == 0x000290, "Member 'UW_CamControlButton_C::Drone_Texture' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Cam_State_Changed) == 0x000298, "Member 'UW_CamControlButton_C::Cam_State_Changed' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Camera) == 0x0002A8, "Member 'UW_CamControlButton_C::Camera' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Cam_Active) == 0x0002B0, "Member 'UW_CamControlButton_C::Cam_Active' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Action) == 0x0002B8, "Member 'UW_CamControlButton_C::Action' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, SQ_PC) == 0x0002C0, "Member 'UW_CamControlButton_C::SQ_PC' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Force_Allowed) == 0x0002C8, "Member 'UW_CamControlButton_C::Force_Allowed' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, WorldSettings) == 0x0002D0, "Member 'UW_CamControlButton_C::WorldSettings' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Command_Condition) == 0x0002D8, "Member 'UW_CamControlButton_C::Command_Condition' has a wrong offset!");
static_assert(offsetof(UW_CamControlButton_C, Can_Toggle_Camera) == 0x0002E0, "Member 'UW_CamControlButton_C::Can_Toggle_Camera' has a wrong offset!");

}

