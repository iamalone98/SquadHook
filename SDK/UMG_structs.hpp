#pragma once

/*
* SDK generated by Dumper-7
*
* https://github.com/Encryqed/Dumper-7
*/

// Package: UMG

#include "Basic.hpp"

#include "MovieSceneTracks_structs.hpp"
#include "PropertyPath_structs.hpp"
#include "CoreUObject_structs.hpp"
#include "Slate_structs.hpp"
#include "SlateCore_structs.hpp"
#include "Engine_structs.hpp"


namespace SDK
{

// Enum UMG.ESlateAccessibleBehavior
// NumValues: 0x0006
enum class ESlateAccessibleBehavior : uint8
{
	NotAccessible                            = 0,
	Auto                                     = 1,
	Summary                                  = 2,
	Custom                                   = 3,
	ToolTip                                  = 4,
	ESlateAccessibleBehavior_MAX             = 5,
};

// Enum UMG.ESlateVisibility
// NumValues: 0x0006
enum class ESlateVisibility : uint8
{
	Visible                                  = 0,
	Collapsed                                = 1,
	Hidden                                   = 2,
	HitTestInvisible                         = 3,
	SelfHitTestInvisible                     = 4,
	ESlateVisibility_MAX                     = 5,
};

// Enum UMG.EVirtualKeyboardType
// NumValues: 0x0007
enum class EVirtualKeyboardType : uint8
{
	Default                                  = 0,
	Number                                   = 1,
	Web                                      = 2,
	Email                                    = 3,
	Password                                 = 4,
	AlphaNumeric                             = 5,
	EVirtualKeyboardType_MAX                 = 6,
};

// Enum UMG.EWidgetAnimationEvent
// NumValues: 0x0003
enum class EWidgetAnimationEvent : uint8
{
	Started                                  = 0,
	Finished                                 = 1,
	EWidgetAnimationEvent_MAX                = 2,
};

// Enum UMG.EUMGSequencePlayMode
// NumValues: 0x0004
enum class EUMGSequencePlayMode : uint8
{
	Forward                                  = 0,
	Reverse                                  = 1,
	PingPong                                 = 2,
	EUMGSequencePlayMode_MAX                 = 3,
};

// Enum UMG.EWidgetTickFrequency
// NumValues: 0x0003
enum class EWidgetTickFrequency : uint8
{
	Never                                    = 0,
	Auto                                     = 1,
	EWidgetTickFrequency_MAX                 = 2,
};

// Enum UMG.EDragPivot
// NumValues: 0x000B
enum class EDragPivot : uint8
{
	MouseDown                                = 0,
	TopLeft                                  = 1,
	TopCenter                                = 2,
	TopRight                                 = 3,
	CenterLeft                               = 4,
	CenterCenter                             = 5,
	CenterRight                              = 6,
	BottomLeft                               = 7,
	BottomCenter                             = 8,
	BottomRight                              = 9,
	EDragPivot_MAX                           = 10,
};

// Enum UMG.EDynamicBoxType
// NumValues: 0x0007
enum class EDynamicBoxType : uint8
{
	Horizontal                               = 0,
	Vertical                                 = 1,
	Wrap                                     = 2,
	VerticalWrap                             = 3,
	Radial                                   = 4,
	Overlay                                  = 5,
	EDynamicBoxType_MAX                      = 6,
};

// Enum UMG.ESlateSizeRule
// NumValues: 0x0003
enum class ESlateSizeRule : uint8
{
	Automatic                                = 0,
	Fill                                     = 1,
	ESlateSizeRule_MAX                       = 2,
};

// Enum UMG.EWidgetDesignFlags
// NumValues: 0x0005
enum class EWidgetDesignFlags : uint8
{
	None                                     = 0,
	Designing                                = 1,
	ShowOutline                              = 2,
	ExecutePreConstruct                      = 4,
	EWidgetDesignFlags_MAX                   = 5,
};

// Enum UMG.EBindingKind
// NumValues: 0x0003
enum class EBindingKind : uint8
{
	Function                                 = 0,
	Property                                 = 1,
	EBindingKind_MAX                         = 2,
};

// Enum UMG.ETickMode
// NumValues: 0x0004
enum class ETickMode : uint8
{
	Disabled                                 = 0,
	Enabled                                  = 1,
	Automatic                                = 2,
	ETickMode_MAX                            = 3,
};

// Enum UMG.EWindowVisibility
// NumValues: 0x0003
enum class EWindowVisibility : uint8
{
	Visible                                  = 0,
	SelfHitTestInvisible                     = 1,
	EWindowVisibility_MAX                    = 2,
};

// Enum UMG.EWidgetGeometryMode
// NumValues: 0x0003
enum class EWidgetGeometryMode : uint8
{
	Plane                                    = 0,
	Cylinder                                 = 1,
	EWidgetGeometryMode_MAX                  = 2,
};

// Enum UMG.EWidgetBlendMode
// NumValues: 0x0004
enum class EWidgetBlendMode : uint8
{
	Opaque                                   = 0,
	Masked                                   = 1,
	Transparent                              = 2,
	EWidgetBlendMode_MAX                     = 3,
};

// Enum UMG.EWidgetTimingPolicy
// NumValues: 0x0003
enum class EWidgetTimingPolicy : uint8
{
	RealTime                                 = 0,
	GameTime                                 = 1,
	EWidgetTimingPolicy_MAX                  = 2,
};

// Enum UMG.EWidgetSpace
// NumValues: 0x0003
enum class EWidgetSpace : uint8
{
	World                                    = 0,
	Screen                                   = 1,
	EWidgetSpace_MAX                         = 2,
};

// Enum UMG.EWidgetInteractionSource
// NumValues: 0x0005
enum class EWidgetInteractionSource : uint8
{
	World                                    = 0,
	Mouse                                    = 1,
	CenterScreen                             = 2,
	Custom                                   = 3,
	EWidgetInteractionSource_MAX             = 4,
};

// ScriptStruct UMG.EventReply
// 0x00B8 (0x00B8 - 0x0000)
struct alignas(0x08) FEventReply final
{
public:
	uint8                                         Pad_1450[0xB8];                                    // 0x0000(0x00B8)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FEventReply) == 0x000008, "Wrong alignment on FEventReply");
static_assert(sizeof(FEventReply) == 0x0000B8, "Wrong size on FEventReply");

// ScriptStruct UMG.DynamicPropertyPath
// 0x0000 (0x0030 - 0x0030)
struct FDynamicPropertyPath final : public FCachedPropertyPath
{
};
static_assert(alignof(FDynamicPropertyPath) == 0x000008, "Wrong alignment on FDynamicPropertyPath");
static_assert(sizeof(FDynamicPropertyPath) == 0x000030, "Wrong size on FDynamicPropertyPath");

// ScriptStruct UMG.WidgetTransform
// 0x001C (0x001C - 0x0000)
struct FWidgetTransform final
{
public:
	struct FVector2D                              Translation;                                       // 0x0000(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              Scale;                                             // 0x0008(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              Shear;                                             // 0x0010(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         Angle;                                             // 0x0018(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FWidgetTransform) == 0x000004, "Wrong alignment on FWidgetTransform");
static_assert(sizeof(FWidgetTransform) == 0x00001C, "Wrong size on FWidgetTransform");
static_assert(offsetof(FWidgetTransform, Translation) == 0x000000, "Member 'FWidgetTransform::Translation' has a wrong offset!");
static_assert(offsetof(FWidgetTransform, Scale) == 0x000008, "Member 'FWidgetTransform::Scale' has a wrong offset!");
static_assert(offsetof(FWidgetTransform, Shear) == 0x000010, "Member 'FWidgetTransform::Shear' has a wrong offset!");
static_assert(offsetof(FWidgetTransform, Angle) == 0x000018, "Member 'FWidgetTransform::Angle' has a wrong offset!");

// ScriptStruct UMG.NamedSlotBinding
// 0x0010 (0x0010 - 0x0000)
struct FNamedSlotBinding final
{
public:
	class FName                                   Name;                                              // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class UWidget*                                Content;                                           // 0x0008(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, PersistentInstance, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FNamedSlotBinding) == 0x000008, "Wrong alignment on FNamedSlotBinding");
static_assert(sizeof(FNamedSlotBinding) == 0x000010, "Wrong size on FNamedSlotBinding");
static_assert(offsetof(FNamedSlotBinding, Name) == 0x000000, "Member 'FNamedSlotBinding::Name' has a wrong offset!");
static_assert(offsetof(FNamedSlotBinding, Content) == 0x000008, "Member 'FNamedSlotBinding::Content' has a wrong offset!");

// ScriptStruct UMG.SlateMeshVertex
// 0x003C (0x003C - 0x0000)
struct FSlateMeshVertex final
{
public:
	struct FVector2D                              Position;                                          // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FColor                                 Color;                                             // 0x0008(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV0;                                               // 0x000C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV1;                                               // 0x0014(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV2;                                               // 0x001C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV3;                                               // 0x0024(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV4;                                               // 0x002C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FVector2D                              UV5;                                               // 0x0034(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FSlateMeshVertex) == 0x000004, "Wrong alignment on FSlateMeshVertex");
static_assert(sizeof(FSlateMeshVertex) == 0x00003C, "Wrong size on FSlateMeshVertex");
static_assert(offsetof(FSlateMeshVertex, Position) == 0x000000, "Member 'FSlateMeshVertex::Position' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, Color) == 0x000008, "Member 'FSlateMeshVertex::Color' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV0) == 0x00000C, "Member 'FSlateMeshVertex::UV0' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV1) == 0x000014, "Member 'FSlateMeshVertex::UV1' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV2) == 0x00001C, "Member 'FSlateMeshVertex::UV2' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV3) == 0x000024, "Member 'FSlateMeshVertex::UV3' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV4) == 0x00002C, "Member 'FSlateMeshVertex::UV4' has a wrong offset!");
static_assert(offsetof(FSlateMeshVertex, UV5) == 0x000034, "Member 'FSlateMeshVertex::UV5' has a wrong offset!");

// ScriptStruct UMG.PaintContext
// 0x0030 (0x0030 - 0x0000)
struct alignas(0x08) FPaintContext final
{
public:
	uint8                                         Pad_1451[0x30];                                    // 0x0000(0x0030)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FPaintContext) == 0x000008, "Wrong alignment on FPaintContext");
static_assert(sizeof(FPaintContext) == 0x000030, "Wrong size on FPaintContext");

// ScriptStruct UMG.ShapedTextOptions
// 0x0003 (0x0003 - 0x0000)
struct FShapedTextOptions final
{
public:
	uint8                                         bOverride_TextShapingMethod : 1;                   // 0x0000(0x0001)(BitIndex: 0x00, PropSize: 0x0001 (Edit, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
	uint8                                         bOverride_TextFlowDirection : 1;                   // 0x0000(0x0001)(BitIndex: 0x01, PropSize: 0x0001 (Edit, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic))
	ETextShapingMethod                            TextShapingMethod;                                 // 0x0001(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, AdvancedDisplay, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	ETextFlowDirection                            TextFlowDirection;                                 // 0x0002(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, AdvancedDisplay, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FShapedTextOptions) == 0x000001, "Wrong alignment on FShapedTextOptions");
static_assert(sizeof(FShapedTextOptions) == 0x000003, "Wrong size on FShapedTextOptions");
static_assert(offsetof(FShapedTextOptions, TextShapingMethod) == 0x000001, "Member 'FShapedTextOptions::TextShapingMethod' has a wrong offset!");
static_assert(offsetof(FShapedTextOptions, TextFlowDirection) == 0x000002, "Member 'FShapedTextOptions::TextFlowDirection' has a wrong offset!");

// ScriptStruct UMG.AnimationEventBinding
// 0x0028 (0x0028 - 0x0000)
struct FAnimationEventBinding final
{
public:
	class UWidgetAnimation*                       Animation;                                         // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	TDelegate<void()>                             Delegate;                                          // 0x0008(0x0010)(ZeroConstructor, InstancedReference, NoDestructor, NativeAccessSpecifierPublic)
	EWidgetAnimationEvent                         AnimationEvent;                                    // 0x0018(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1452[0x3];                                     // 0x0019(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   UserTag;                                           // 0x001C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1453[0x4];                                     // 0x0024(0x0004)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FAnimationEventBinding) == 0x000008, "Wrong alignment on FAnimationEventBinding");
static_assert(sizeof(FAnimationEventBinding) == 0x000028, "Wrong size on FAnimationEventBinding");
static_assert(offsetof(FAnimationEventBinding, Animation) == 0x000000, "Member 'FAnimationEventBinding::Animation' has a wrong offset!");
static_assert(offsetof(FAnimationEventBinding, Delegate) == 0x000008, "Member 'FAnimationEventBinding::Delegate' has a wrong offset!");
static_assert(offsetof(FAnimationEventBinding, AnimationEvent) == 0x000018, "Member 'FAnimationEventBinding::AnimationEvent' has a wrong offset!");
static_assert(offsetof(FAnimationEventBinding, UserTag) == 0x00001C, "Member 'FAnimationEventBinding::UserTag' has a wrong offset!");

// ScriptStruct UMG.AnchorData
// 0x0028 (0x0028 - 0x0000)
struct FAnchorData final
{
public:
	struct FMargin                                Offsets;                                           // 0x0000(0x0010)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, NativeAccessSpecifierPublic)
	struct FAnchors                               Anchors;                                           // 0x0010(0x0010)(Edit, BlueprintVisible, NoDestructor, NativeAccessSpecifierPublic)
	struct FVector2D                              Alignment;                                         // 0x0020(0x0008)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FAnchorData) == 0x000004, "Wrong alignment on FAnchorData");
static_assert(sizeof(FAnchorData) == 0x000028, "Wrong size on FAnchorData");
static_assert(offsetof(FAnchorData, Offsets) == 0x000000, "Member 'FAnchorData::Offsets' has a wrong offset!");
static_assert(offsetof(FAnchorData, Anchors) == 0x000010, "Member 'FAnchorData::Anchors' has a wrong offset!");
static_assert(offsetof(FAnchorData, Alignment) == 0x000020, "Member 'FAnchorData::Alignment' has a wrong offset!");

// ScriptStruct UMG.MovieScene2DTransformMask
// 0x0004 (0x0004 - 0x0000)
struct FMovieScene2DTransformMask final
{
public:
	uint32                                        Mask;                                              // 0x0000(0x0004)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPrivate)
};
static_assert(alignof(FMovieScene2DTransformMask) == 0x000004, "Wrong alignment on FMovieScene2DTransformMask");
static_assert(sizeof(FMovieScene2DTransformMask) == 0x000004, "Wrong size on FMovieScene2DTransformMask");
static_assert(offsetof(FMovieScene2DTransformMask, Mask) == 0x000000, "Member 'FMovieScene2DTransformMask::Mask' has a wrong offset!");

// ScriptStruct UMG.MovieSceneWidgetMaterialSectionTemplate
// 0x0010 (0x0090 - 0x0080)
struct FMovieSceneWidgetMaterialSectionTemplate final : public FMovieSceneParameterSectionTemplate
{
public:
	TArray<class FName>                           BrushPropertyNamePath;                             // 0x0080(0x0010)(ZeroConstructor, NativeAccessSpecifierPrivate)
};
static_assert(alignof(FMovieSceneWidgetMaterialSectionTemplate) == 0x000008, "Wrong alignment on FMovieSceneWidgetMaterialSectionTemplate");
static_assert(sizeof(FMovieSceneWidgetMaterialSectionTemplate) == 0x000090, "Wrong size on FMovieSceneWidgetMaterialSectionTemplate");
static_assert(offsetof(FMovieSceneWidgetMaterialSectionTemplate, BrushPropertyNamePath) == 0x000080, "Member 'FMovieSceneWidgetMaterialSectionTemplate::BrushPropertyNamePath' has a wrong offset!");

// ScriptStruct UMG.RadialBoxSettings
// 0x0010 (0x0010 - 0x0000)
struct FRadialBoxSettings final
{
public:
	float                                         StartingAngle;                                     // 0x0000(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	bool                                          bDistributeItemsEvenly;                            // 0x0004(0x0001)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1454[0x3];                                     // 0x0005(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	float                                         AngleBetweenItems;                                 // 0x0008(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	float                                         SectorCentralAngle;                                // 0x000C(0x0004)(Edit, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FRadialBoxSettings) == 0x000004, "Wrong alignment on FRadialBoxSettings");
static_assert(sizeof(FRadialBoxSettings) == 0x000010, "Wrong size on FRadialBoxSettings");
static_assert(offsetof(FRadialBoxSettings, StartingAngle) == 0x000000, "Member 'FRadialBoxSettings::StartingAngle' has a wrong offset!");
static_assert(offsetof(FRadialBoxSettings, bDistributeItemsEvenly) == 0x000004, "Member 'FRadialBoxSettings::bDistributeItemsEvenly' has a wrong offset!");
static_assert(offsetof(FRadialBoxSettings, AngleBetweenItems) == 0x000008, "Member 'FRadialBoxSettings::AngleBetweenItems' has a wrong offset!");
static_assert(offsetof(FRadialBoxSettings, SectorCentralAngle) == 0x00000C, "Member 'FRadialBoxSettings::SectorCentralAngle' has a wrong offset!");

// ScriptStruct UMG.RichTextStyleRow
// 0x0270 (0x0278 - 0x0008)
struct FRichTextStyleRow final : public FTableRowBase
{
public:
	struct FTextBlockStyle                        TextStyle;                                         // 0x0008(0x0270)(Edit, NativeAccessSpecifierPublic)
};
static_assert(alignof(FRichTextStyleRow) == 0x000008, "Wrong alignment on FRichTextStyleRow");
static_assert(sizeof(FRichTextStyleRow) == 0x000278, "Wrong size on FRichTextStyleRow");
static_assert(offsetof(FRichTextStyleRow, TextStyle) == 0x000008, "Member 'FRichTextStyleRow::TextStyle' has a wrong offset!");

// ScriptStruct UMG.RichImageRow
// 0x0088 (0x0090 - 0x0008)
struct FRichImageRow final : public FTableRowBase
{
public:
	struct FSlateBrush                            Brush;                                             // 0x0008(0x0088)(Edit, NativeAccessSpecifierPublic)
};
static_assert(alignof(FRichImageRow) == 0x000008, "Wrong alignment on FRichImageRow");
static_assert(sizeof(FRichImageRow) == 0x000090, "Wrong size on FRichImageRow");
static_assert(offsetof(FRichImageRow, Brush) == 0x000008, "Member 'FRichImageRow::Brush' has a wrong offset!");

// ScriptStruct UMG.SlateChildSize
// 0x0008 (0x0008 - 0x0000)
struct FSlateChildSize final
{
public:
	float                                         Value;                                             // 0x0000(0x0004)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	ESlateSizeRule                                SizeRule;                                          // 0x0004(0x0001)(Edit, BlueprintVisible, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1455[0x3];                                     // 0x0005(0x0003)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FSlateChildSize) == 0x000004, "Wrong alignment on FSlateChildSize");
static_assert(sizeof(FSlateChildSize) == 0x000008, "Wrong size on FSlateChildSize");
static_assert(offsetof(FSlateChildSize, Value) == 0x000000, "Member 'FSlateChildSize::Value' has a wrong offset!");
static_assert(offsetof(FSlateChildSize, SizeRule) == 0x000004, "Member 'FSlateChildSize::SizeRule' has a wrong offset!");

// ScriptStruct UMG.UserWidgetPool
// 0x0080 (0x0080 - 0x0000)
struct FUserWidgetPool final
{
public:
	TArray<class UUserWidget*>                    ActiveWidgets;                                     // 0x0000(0x0010)(ExportObject, ZeroConstructor, Transient, ContainsInstancedReference, NativeAccessSpecifierPrivate)
	TArray<class UUserWidget*>                    InactiveWidgets;                                   // 0x0010(0x0010)(ExportObject, ZeroConstructor, Transient, ContainsInstancedReference, NativeAccessSpecifierPrivate)
	uint8                                         Pad_1456[0x60];                                    // 0x0020(0x0060)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FUserWidgetPool) == 0x000008, "Wrong alignment on FUserWidgetPool");
static_assert(sizeof(FUserWidgetPool) == 0x000080, "Wrong size on FUserWidgetPool");
static_assert(offsetof(FUserWidgetPool, ActiveWidgets) == 0x000000, "Member 'FUserWidgetPool::ActiveWidgets' has a wrong offset!");
static_assert(offsetof(FUserWidgetPool, InactiveWidgets) == 0x000010, "Member 'FUserWidgetPool::InactiveWidgets' has a wrong offset!");

// ScriptStruct UMG.WidgetAnimationBinding
// 0x0024 (0x0024 - 0x0000)
struct FWidgetAnimationBinding final
{
public:
	class FName                                   WidgetName;                                        // 0x0000(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   SlotWidgetName;                                    // 0x0008(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FGuid                                  AnimationGuid;                                     // 0x0010(0x0010)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	bool                                          bIsRootWidget;                                     // 0x0020(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1457[0x3];                                     // 0x0021(0x0003)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FWidgetAnimationBinding) == 0x000004, "Wrong alignment on FWidgetAnimationBinding");
static_assert(sizeof(FWidgetAnimationBinding) == 0x000024, "Wrong size on FWidgetAnimationBinding");
static_assert(offsetof(FWidgetAnimationBinding, WidgetName) == 0x000000, "Member 'FWidgetAnimationBinding::WidgetName' has a wrong offset!");
static_assert(offsetof(FWidgetAnimationBinding, SlotWidgetName) == 0x000008, "Member 'FWidgetAnimationBinding::SlotWidgetName' has a wrong offset!");
static_assert(offsetof(FWidgetAnimationBinding, AnimationGuid) == 0x000010, "Member 'FWidgetAnimationBinding::AnimationGuid' has a wrong offset!");
static_assert(offsetof(FWidgetAnimationBinding, bIsRootWidget) == 0x000020, "Member 'FWidgetAnimationBinding::bIsRootWidget' has a wrong offset!");

// ScriptStruct UMG.BlueprintWidgetAnimationDelegateBinding
// 0x001C (0x001C - 0x0000)
struct FBlueprintWidgetAnimationDelegateBinding final
{
public:
	EWidgetAnimationEvent                         Action;                                            // 0x0000(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1458[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   AnimationToBind;                                   // 0x0004(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   FunctionNameToBind;                                // 0x000C(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   UserTag;                                           // 0x0014(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
};
static_assert(alignof(FBlueprintWidgetAnimationDelegateBinding) == 0x000004, "Wrong alignment on FBlueprintWidgetAnimationDelegateBinding");
static_assert(sizeof(FBlueprintWidgetAnimationDelegateBinding) == 0x00001C, "Wrong size on FBlueprintWidgetAnimationDelegateBinding");
static_assert(offsetof(FBlueprintWidgetAnimationDelegateBinding, Action) == 0x000000, "Member 'FBlueprintWidgetAnimationDelegateBinding::Action' has a wrong offset!");
static_assert(offsetof(FBlueprintWidgetAnimationDelegateBinding, AnimationToBind) == 0x000004, "Member 'FBlueprintWidgetAnimationDelegateBinding::AnimationToBind' has a wrong offset!");
static_assert(offsetof(FBlueprintWidgetAnimationDelegateBinding, FunctionNameToBind) == 0x00000C, "Member 'FBlueprintWidgetAnimationDelegateBinding::FunctionNameToBind' has a wrong offset!");
static_assert(offsetof(FBlueprintWidgetAnimationDelegateBinding, UserTag) == 0x000014, "Member 'FBlueprintWidgetAnimationDelegateBinding::UserTag' has a wrong offset!");

// ScriptStruct UMG.DelegateRuntimeBinding
// 0x0058 (0x0058 - 0x0000)
struct FDelegateRuntimeBinding final
{
public:
	class FString                                 ObjectName;                                        // 0x0000(0x0010)(ZeroConstructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   PropertyName;                                      // 0x0010(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	class FName                                   FunctionName;                                      // 0x0018(0x0008)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	struct FDynamicPropertyPath                   SourcePath;                                        // 0x0020(0x0030)(NativeAccessSpecifierPublic)
	EBindingKind                                  Kind;                                              // 0x0050(0x0001)(ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_1459[0x7];                                     // 0x0051(0x0007)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FDelegateRuntimeBinding) == 0x000008, "Wrong alignment on FDelegateRuntimeBinding");
static_assert(sizeof(FDelegateRuntimeBinding) == 0x000058, "Wrong size on FDelegateRuntimeBinding");
static_assert(offsetof(FDelegateRuntimeBinding, ObjectName) == 0x000000, "Member 'FDelegateRuntimeBinding::ObjectName' has a wrong offset!");
static_assert(offsetof(FDelegateRuntimeBinding, PropertyName) == 0x000010, "Member 'FDelegateRuntimeBinding::PropertyName' has a wrong offset!");
static_assert(offsetof(FDelegateRuntimeBinding, FunctionName) == 0x000018, "Member 'FDelegateRuntimeBinding::FunctionName' has a wrong offset!");
static_assert(offsetof(FDelegateRuntimeBinding, SourcePath) == 0x000020, "Member 'FDelegateRuntimeBinding::SourcePath' has a wrong offset!");
static_assert(offsetof(FDelegateRuntimeBinding, Kind) == 0x000050, "Member 'FDelegateRuntimeBinding::Kind' has a wrong offset!");

// ScriptStruct UMG.WidgetComponentInstanceData
// 0x0010 (0x00C8 - 0x00B8)
struct FWidgetComponentInstanceData final : public FSceneComponentInstanceData
{
public:
	uint8                                         Pad_145A[0x10];                                    // 0x00B8(0x0010)(Fixing Struct Size After Last Property [ Dumper-7 ])
};
static_assert(alignof(FWidgetComponentInstanceData) == 0x000008, "Wrong alignment on FWidgetComponentInstanceData");
static_assert(sizeof(FWidgetComponentInstanceData) == 0x0000C8, "Wrong size on FWidgetComponentInstanceData");

// ScriptStruct UMG.WidgetNavigationData
// 0x0024 (0x0024 - 0x0000)
struct FWidgetNavigationData final
{
public:
	EUINavigationRule                             Rule;                                              // 0x0000(0x0001)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	uint8                                         Pad_145B[0x3];                                     // 0x0001(0x0003)(Fixing Size After Last Property [ Dumper-7 ])
	class FName                                   WidgetToFocus;                                     // 0x0004(0x0008)(Edit, BlueprintVisible, BlueprintReadOnly, ZeroConstructor, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	TWeakObjectPtr<class UWidget>                 Widget;                                            // 0x000C(0x0008)(ExportObject, ZeroConstructor, InstancedReference, IsPlainOldData, NoDestructor, UObjectWrapper, HasGetValueTypeHash, NativeAccessSpecifierPublic)
	TDelegate<void(EUINavigation Navigation)>     CustomDelegate;                                    // 0x0014(0x0010)(ZeroConstructor, InstancedReference, NoDestructor, NativeAccessSpecifierPublic)
};
static_assert(alignof(FWidgetNavigationData) == 0x000004, "Wrong alignment on FWidgetNavigationData");
static_assert(sizeof(FWidgetNavigationData) == 0x000024, "Wrong size on FWidgetNavigationData");
static_assert(offsetof(FWidgetNavigationData, Rule) == 0x000000, "Member 'FWidgetNavigationData::Rule' has a wrong offset!");
static_assert(offsetof(FWidgetNavigationData, WidgetToFocus) == 0x000004, "Member 'FWidgetNavigationData::WidgetToFocus' has a wrong offset!");
static_assert(offsetof(FWidgetNavigationData, Widget) == 0x00000C, "Member 'FWidgetNavigationData::Widget' has a wrong offset!");
static_assert(offsetof(FWidgetNavigationData, CustomDelegate) == 0x000014, "Member 'FWidgetNavigationData::CustomDelegate' has a wrong offset!");

}

