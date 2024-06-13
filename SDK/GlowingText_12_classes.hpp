#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: GlowingText_12

#include "Basic.hpp"

#include "Engine_structs.hpp"
#include "UMG_classes.hpp"


namespace SDK
{

// WidgetBlueprintGeneratedClass GlowingText_12.GlowingText_12_C
// 0x0040 (0x02A0 - 0x0260)
class UGlowingText_12_C final : public UUserWidget
{
public:
	struct FPointerToUberGraphFrame               UberGraphFrame;                                    // 0x0260(0x0008)(ZeroConstructor, Transient, DuplicateTransient)
	class UTextBlock*                             CenterTextBlock;                                   // 0x0268(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               Glow;                                              // 0x0270(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class UOverlay*                               TextOverlay;                                       // 0x0278(0x0008)(BlueprintVisible, ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, RepSkip, NoDestructor, PersistentInstance, HasGetValueTypeHash)
	class FText                                   ButtonText;                                        // 0x0280(0x0018)(Edit, BlueprintVisible)
	bool                                          bShowShadow;                                       // 0x0298(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)
	bool                                          bAutoInit;                                         // 0x0299(0x0001)(Edit, BlueprintVisible, ZeroConstructor, DisableEditOnInstance, IsPlainOldData, NoDestructor)

public:
	void ExecuteUbergraph_GlowingText_12(int32 EntryPoint);
	void PreConstruct(bool IsDesignTime);
	void Construct();
	void SetGlowing(bool bGlowing);
	void Init(const class FText& Text, bool Param_bShowShadow);
	void Update();
	void SetText(const class FText& Text);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"GlowingText_12_C">();
	}
	static class UGlowingText_12_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<UGlowingText_12_C>();
	}
};
static_assert(alignof(UGlowingText_12_C) == 0x000008, "Wrong alignment on UGlowingText_12_C");
static_assert(sizeof(UGlowingText_12_C) == 0x0002A0, "Wrong size on UGlowingText_12_C");
static_assert(offsetof(UGlowingText_12_C, UberGraphFrame) == 0x000260, "Member 'UGlowingText_12_C::UberGraphFrame' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, CenterTextBlock) == 0x000268, "Member 'UGlowingText_12_C::CenterTextBlock' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, Glow) == 0x000270, "Member 'UGlowingText_12_C::Glow' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, TextOverlay) == 0x000278, "Member 'UGlowingText_12_C::TextOverlay' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, ButtonText) == 0x000280, "Member 'UGlowingText_12_C::ButtonText' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, bShowShadow) == 0x000298, "Member 'UGlowingText_12_C::bShowShadow' has a wrong offset!");
static_assert(offsetof(UGlowingText_12_C, bAutoInit) == 0x000299, "Member 'UGlowingText_12_C::bAutoInit' has a wrong offset!");

}

