#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: Hotfix

#include "Basic.hpp"


namespace SDK
{

// Enum Hotfix.EHotfixResult
// NumValues: 0x0006
enum class EHotfixResult : uint8
{
	Failed                                   = 0,
	Success                                  = 1,
	SuccessNoChange                          = 2,
	SuccessNeedsReload                       = 3,
	SuccessNeedsRelaunch                     = 4,
	EHotfixResult_MAX                        = 5,
};

// Enum Hotfix.EUpdateCompletionStatus
// NumValues: 0x000A
enum class EUpdateCompletionStatus : uint8
{
	UpdateUnknown                            = 0,
	UpdateSuccess                            = 1,
	UpdateSuccess_NoChange                   = 2,
	UpdateSuccess_NeedsReload                = 3,
	UpdateSuccess_NeedsRelaunch              = 4,
	UpdateSuccess_NeedsPatch                 = 5,
	UpdateFailure_PatchCheck                 = 6,
	UpdateFailure_HotfixCheck                = 7,
	UpdateFailure_NotLoggedIn                = 8,
	EUpdateCompletionStatus_MAX              = 9,
};

// Enum Hotfix.EUpdateState
// NumValues: 0x0009
enum class EUpdateState : uint8
{
	UpdateIdle                               = 0,
	UpdatePending                            = 1,
	CheckingForPatch                         = 2,
	DetectingPlatformEnvironment             = 3,
	CheckingForHotfix                        = 4,
	WaitingOnInitialLoad                     = 5,
	InitialLoadComplete                      = 6,
	UpdateComplete                           = 7,
	EUpdateState_MAX                         = 8,
};

}
