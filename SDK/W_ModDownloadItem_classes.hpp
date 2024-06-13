#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: W_ModDownloadItem

#include "Basic.hpp"

#include "ModdingRuntime_structs.hpp"
#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass W_ModDownloadItem.W_ModDownloadItem_C
// 0x00D0 (0x0330 - 0x0260)
class UW_ModDownloadItem_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UWidgetAnimation*                       BounceAnim;                                        // 0x0268(0x0008)(BlueprintVisible, BlueprintReadOnly, ZeroConstructor, Transient, IsPlainOldData, RepSkip, NoDestructor, HasGetValueTypeHash)
	class UButton*                                Button_Mod;                                        // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UCircularThrobber*                      CircularThrobber_0;                                // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UProgressBar*                           DownloadProgressBar;                               // 0x0280(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 Image_0;                                           // 0x0288(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UImage*                                 ModIcon;                                           // 0x0290(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UBorder*                                Prog_BG;                                           // 0x0298(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_DownloadState;                                  // 0x02A0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UTextBlock*                             TB_ModName;                                        // 0x02A8(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UWidgetSwitcher*                        WidgetSwitcher_0;                                  // 0x02B0(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	struct FSQModInfo                             ModInfo;                                           // 0x02B8(0x0050)(Edit, BlueprintVisible)
	class UTexture2DDynamic*                      Texture;                                           // 0x0308(0x0008)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	bool                                          NewVar_0;                                          // 0x0310(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	uint8                                         Pad_3ACB[0x7];                                     // 0x0311(0x0007)(Fixing Size After Last Property [ Dumper-7 ])
	class UW_ModDownloadWindow_C*                 ModDownloadWindow;                                 // 0x0318(0x0008)(Edit, BlueprintVisible, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	int32                                         Mod_Download_Index;                                // 0x0320(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)
	uint8                                         Pad_3ACC[0x4];                                     // 0x0324(0x0004)(Fixing Size After Last Property [ Dumper-7 ])
	class USQSessionInfo*                         SessionInfo;                                       // 0x0328(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, ExposeOnSpawn, HasGetValueTypeHash)

public:
	void ExecuteUbergraph_W_ModDownloadItem(int32 EntryPoint);
	void BndEvt__Button_Mod_K2Node_ComponentBoundEvent_0_OnButtonClickedEvent__DelegateSignature();
	void Tick(const struct FGeometry& MyGeometry, float InDeltaTime);
	void Wait_for_Mod_Loading();
	void BndEvt__Button_Mod_K2Node_ComponentBoundEvent_236_OnButtonHoverEvent__DelegateSignature();
	void BndEvt__Button_Mod_K2Node_ComponentBoundEvent_226_OnButtonHoverEvent__DelegateSignature();
	void Construct();
	void OnSuccess_9FEB735B449DA3B1D8BC1A99168DFA92(class UTexture2DDynamic* Param_Texture);
	void OnFail_9FEB735B449DA3B1D8BC1A99168DFA92(class UTexture2DDynamic* Param_Texture);
	void Refresh_Mod();
	struct FLinearColor Get_ModIcon_ColorAndOpacity_0();
	void Update_Download_Status();

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"W_ModDownloadItem_C">();
	}
	static class UW_ModDownloadItem_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UW_ModDownloadItem_C>();
	}
};
static_assert(alignof(UW_ModDownloadItem_C) == 0x000008, "Wrong alignment on UW_ModDownloadItem_C");
static_assert(sizeof(UW_ModDownloadItem_C) == 0x000330, "Wrong size on UW_ModDownloadItem_C");
static_assert(offsetof(UW_ModDownloadItem_C, UberGraphFrame) == 0x000260, "Member 'UW_ModDownloadItem_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, BounceAnim) == 0x000268, "Member 'UW_ModDownloadItem_C::BounceAnim' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, Button_Mod) == 0x000270, "Member 'UW_ModDownloadItem_C::Button_Mod' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, CircularThrobber_0) == 0x000278, "Member 'UW_ModDownloadItem_C::CircularThrobber_0' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, DownloadProgressBar) == 0x000280, "Member 'UW_ModDownloadItem_C::DownloadProgressBar' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, Image_0) == 0x000288, "Member 'UW_ModDownloadItem_C::Image_0' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, ModIcon) == 0x000290, "Member 'UW_ModDownloadItem_C::ModIcon' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, Prog_BG) == 0x000298, "Member 'UW_ModDownloadItem_C::Prog_BG' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, TB_DownloadState) == 0x0002A0, "Member 'UW_ModDownloadItem_C::TB_DownloadState' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, TB_ModName) == 0x0002A8, "Member 'UW_ModDownloadItem_C::TB_ModName' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, WidgetSwitcher_0) == 0x0002B0, "Member 'UW_ModDownloadItem_C::WidgetSwitcher_0' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, ModInfo) == 0x0002B8, "Member 'UW_ModDownloadItem_C::ModInfo' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, Texture) == 0x000308, "Member 'UW_ModDownloadItem_C::Texture' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, NewVar_0) == 0x000310, "Member 'UW_ModDownloadItem_C::NewVar_0' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, ModDownloadWindow) == 0x000318, "Member 'UW_ModDownloadItem_C::ModDownloadWindow' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, Mod_Download_Index) == 0x000320, "Member 'UW_ModDownloadItem_C::Mod_Download_Index' has a wrong offset!");
static_assert(offsetof(UW_ModDownloadItem_C, SessionInfo) == 0x000328, "Member 'UW_ModDownloadItem_C::SessionInfo' has a wrong offset!");

}
