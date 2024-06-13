#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: S_MainNotification

#include "Basic.hpp"

#include "CoreUObject_structs.hpp"


namespace SDK
{

// UserDefinedStruct S_MainNotification.S_MainNotification
// 0x0028 (0x0028 - 0x0000)
struct FS_MainNotification final
{
public:
	class FString                                 Message_10_859C40E04544AD6235485AA56AF0DB84;       // 0x0000(0x0010)(Edit, BlueprintVisible, ZeroConstructor, HasGetValueTypeHash)
	float                                         Duration_9_DE1EEDD6427551BA55471EAD56C8995E;       // 0x0010(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
	struct FLinearColor                           Color_12_0153DDF2416865175A5C188D9AB10331;         // 0x0014(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash)
};
static_assert(alignof(FS_MainNotification) == 0x000008, "Wrong alignment on FS_MainNotification");
static_assert(sizeof(FS_MainNotification) == 0x000028, "Wrong size on FS_MainNotification");
static_assert(offsetof(FS_MainNotification, Message_10_859C40E04544AD6235485AA56AF0DB84) == 0x000000, "Member 'FS_MainNotification::Message_10_859C40E04544AD6235485AA56AF0DB84' has a wrong offset!");
static_assert(offsetof(FS_MainNotification, Duration_9_DE1EEDD6427551BA55471EAD56C8995E) == 0x000010, "Member 'FS_MainNotification::Duration_9_DE1EEDD6427551BA55471EAD56C8995E' has a wrong offset!");
static_assert(offsetof(FS_MainNotification, Color_12_0153DDF2416865175A5C188D9AB10331) == 0x000014, "Member 'FS_MainNotification::Color_12_0153DDF2416865175A5C188D9AB10331' has a wrong offset!");

}
