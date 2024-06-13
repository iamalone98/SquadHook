#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Library_SquadUI

#include "Basic.hpp"

#include "Engine_classes.hpp"
#include "MicrophoneVolume_structs.hpp"
#include "Squad_structs.hpp"


namespace SDK
{

// BlueprintGeneratedClass Library_SquadUI.Library_SquadUI_C
// 0x0000 (0x0028 - 0x0028)
class ULibrary_SquadUI_C final : public UBlueprintFunctionLibrary
{
public:
	static void Get_UI_Save_Data(class UObject* __WorldContext, class USaveData_UI_C** UI_Save_Data);
	static void Save_UI_Save_Data(class USaveData_UI_C* SaveGameObject, class UObject* __WorldContext);
	static void Get_SQHUD_Colors(class UObject* __WorldContext, class USQColorsDataAsset** ColorsDataAsset);
	static void Add_Notification(const class FText& Text, ESQNotificationTypes Type, class UTexture2D* Custom_Icon, const struct FLinearColor& CustomIconColor, bool PreventRepetition, class UObject* __WorldContext);
	static void GetShortName(class FName InputPin, class UObject* __WorldContext, class FText* Short_Name);
	static void GetMicrophoneVolume(class UObject* __WorldContext, EMicrophoneVolume* DiscreteVolume);

	void ParseKeybind(const class FString& InString, class UObject* __WorldContext, class FText* Short_Name);

public:
	static class UClass* StaticClass()
	{
		return StaticBPGeneratedClassImpl<"Library_SquadUI_C">();
	}
	static class ULibrary_SquadUI_C* GetDefaultObj()
	{
		return GetDefaultObjImpl<ULibrary_SquadUI_C>();
	}
};
static_assert(alignof(ULibrary_SquadUI_C) == 0x000008, "Wrong alignment on ULibrary_SquadUI_C");
static_assert(sizeof(ULibrary_SquadUI_C) == 0x000028, "Wrong size on ULibrary_SquadUI_C");

}
