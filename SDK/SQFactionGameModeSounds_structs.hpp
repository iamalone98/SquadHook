#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: SQFactionGameModeSounds

#include "Basic.hpp"


namespace SDK
{

// UserDefinedStruct SQFactionGameModeSounds.SQFactionGameModeSounds
// 0x0078 (0x0078 - 0x0000)
struct FSQFactionGameModeSounds final
{
public:
	TSoftObjectPtr<class USoundCue>               AttackerCue_2_8CEEDA4A43116E8679EC63B5A8BDA448;    // 0x0000(0x0028)(Edit, BlueprintVisible, HasGetValueTypeHash)
	TSoftObjectPtr<class USoundCue>               DefenderCue_7_AFAEE0D84A23631C0D42E7910174FD52;    // 0x0028(0x0028)(Edit, BlueprintVisible, HasGetValueTypeHash)
	TSoftObjectPtr<class USoundCue>               OtherCue_8_B8CF01914B7ABCDEDAD53DB45785EED5;       // 0x0050(0x0028)(Edit, BlueprintVisible, HasGetValueTypeHash)
};
static_assert(alignof(FSQFactionGameModeSounds) == 0x000008, "Wrong alignment on FSQFactionGameModeSounds");
static_assert(sizeof(FSQFactionGameModeSounds) == 0x000078, "Wrong size on FSQFactionGameModeSounds");
static_assert(offsetof(FSQFactionGameModeSounds, AttackerCue_2_8CEEDA4A43116E8679EC63B5A8BDA448) == 0x000000, "Member 'FSQFactionGameModeSounds::AttackerCue_2_8CEEDA4A43116E8679EC63B5A8BDA448' has a wrong offset!");
static_assert(offsetof(FSQFactionGameModeSounds, DefenderCue_7_AFAEE0D84A23631C0D42E7910174FD52) == 0x000028, "Member 'FSQFactionGameModeSounds::DefenderCue_7_AFAEE0D84A23631C0D42E7910174FD52' has a wrong offset!");
static_assert(offsetof(FSQFactionGameModeSounds, OtherCue_8_B8CF01914B7ABCDEDAD53DB45785EED5) == 0x000050, "Member 'FSQFactionGameModeSounds::OtherCue_8_B8CF01914B7ABCDEDAD53DB45785EED5' has a wrong offset!");

}

