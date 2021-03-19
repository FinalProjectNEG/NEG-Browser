// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/test/animation_test_common.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "cc/animation/animation.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation_id_provider.h"
#include "cc/animation/element_animations.h"
#include "cc/animation/keyframe_effect.h"
#include "cc/animation/keyframed_animation_curve.h"
#include "cc/animation/scroll_offset_animation_curve.h"
#include "cc/animation/scroll_offset_animation_curve_factory.h"
#include "cc/animation/timing_function.h"
#include "cc/animation/transform_operations.h"
#include "cc/layers/layer.h"
#include "cc/layers/layer_impl.h"

using cc::KeyframeModel;
using cc::AnimationCurve;
using cc::FloatKeyframe;
using cc::KeyframedFloatAnimationCurve;
using cc::KeyframedTransformAnimationCurve;
using cc::TimingFunction;
using cc::TransformKeyframe;

namespace cc {

int AddOpacityTransition(Animation* target,
                         double duration,
                         float start_opacity,
                         float end_opacity,
                         bool use_timing_function) {
  std::unique_ptr<KeyframedFloatAnimationCurve> curve(
      KeyframedFloatAnimationCurve::Create());

  std::unique_ptr<TimingFunction> func;
  if (!use_timing_function)
    func = CubicBezierTimingFunction::CreatePreset(
        CubicBezierTimingFunction::EaseType::EASE);
  if (duration > 0.0)
    curve->AddKeyframe(FloatKeyframe::Create(base::TimeDelta(), start_opacity,
                                             std::move(func)));
  curve->AddKeyframe(FloatKeyframe::Create(
      base::TimeDelta::FromSecondsD(duration), end_opacity, nullptr));

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::OPACITY));
  keyframe_model->set_needs_synchronized_start_time(true);

  target->AddKeyframeModel(std::move(keyframe_model));
  return id;
}

int AddAnimatedTransform(Animation* target,
                         double duration,
                         TransformOperations start_operations,
                         TransformOperations operations) {
  std::unique_ptr<KeyframedTransformAnimationCurve> curve(
      KeyframedTransformAnimationCurve::Create());

  if (duration > 0.0) {
    curve->AddKeyframe(TransformKeyframe::Create(base::TimeDelta(),
                                                 start_operations, nullptr));
  }

  curve->AddKeyframe(TransformKeyframe::Create(
      base::TimeDelta::FromSecondsD(duration), operations, nullptr));

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::TRANSFORM));
  keyframe_model->set_needs_synchronized_start_time(true);

  target->AddKeyframeModel(std::move(keyframe_model));
  return id;
}

int AddAnimatedTransform(Animation* target,
                         double duration,
                         int delta_x,
                         int delta_y) {
  TransformOperations start_operations;
  if (duration > 0.0) {
    start_operations.AppendTranslate(0, 0, 0.0);
  }

  TransformOperations operations;
  operations.AppendTranslate(delta_x, delta_y, 0.0);
  return AddAnimatedTransform(target, duration, start_operations, operations);
}

int AddAnimatedFilter(Animation* target,
                      double duration,
                      float start_brightness,
                      float end_brightness) {
  std::unique_ptr<KeyframedFilterAnimationCurve> curve(
      KeyframedFilterAnimationCurve::Create());

  if (duration > 0.0) {
    FilterOperations start_filters;
    start_filters.Append(
        FilterOperation::CreateBrightnessFilter(start_brightness));
    curve->AddKeyframe(
        FilterKeyframe::Create(base::TimeDelta(), start_filters, nullptr));
  }

  FilterOperations filters;
  filters.Append(FilterOperation::CreateBrightnessFilter(end_brightness));
  curve->AddKeyframe(FilterKeyframe::Create(
      base::TimeDelta::FromSecondsD(duration), filters, nullptr));

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::FILTER));
  keyframe_model->set_needs_synchronized_start_time(true);

  target->AddKeyframeModel(std::move(keyframe_model));
  return id;
}

int AddAnimatedBackdropFilter(Animation* target,
                              double duration,
                              float start_invert,
                              float end_invert) {
  std::unique_ptr<KeyframedFilterAnimationCurve> curve(
      KeyframedFilterAnimationCurve::Create());

  if (duration > 0.0) {
    FilterOperations start_filters;
    start_filters.Append(FilterOperation::CreateInvertFilter(start_invert));
    curve->AddKeyframe(
        FilterKeyframe::Create(base::TimeDelta(), start_filters, nullptr));
  }

  FilterOperations filters;
  filters.Append(FilterOperation::CreateInvertFilter(end_invert));
  curve->AddKeyframe(FilterKeyframe::Create(
      base::TimeDelta::FromSecondsD(duration), filters, nullptr));

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::BACKDROP_FILTER));
  keyframe_model->set_needs_synchronized_start_time(true);

  target->AddKeyframeModel(std::move(keyframe_model));
  return id;
}

FakeFloatAnimationCurve::FakeFloatAnimationCurve()
    : duration_(base::TimeDelta::FromSecondsD(1.0)) {
}

FakeFloatAnimationCurve::FakeFloatAnimationCurve(double duration)
    : duration_(base::TimeDelta::FromSecondsD(duration)) {
}

FakeFloatAnimationCurve::~FakeFloatAnimationCurve() = default;

base::TimeDelta FakeFloatAnimationCurve::Duration() const {
  return duration_;
}

float FakeFloatAnimationCurve::GetValue(base::TimeDelta now) const {
  return 0.0f;
}

std::unique_ptr<AnimationCurve> FakeFloatAnimationCurve::Clone() const {
  return base::WrapUnique(new FakeFloatAnimationCurve);
}

FakeTransformTransition::FakeTransformTransition(double duration)
    : duration_(base::TimeDelta::FromSecondsD(duration)) {
}

FakeTransformTransition::~FakeTransformTransition() = default;

base::TimeDelta FakeTransformTransition::Duration() const {
  return duration_;
}

TransformOperations FakeTransformTransition::GetValue(
    base::TimeDelta time) const {
  return TransformOperations();
}

bool FakeTransformTransition::IsTranslation() const { return true; }

bool FakeTransformTransition::PreservesAxisAlignment() const {
  return true;
}

bool FakeTransformTransition::AnimationStartScale(bool forward_direction,
                                                  float* start_scale) const {
  *start_scale = 1.f;
  return true;
}

bool FakeTransformTransition::MaximumTargetScale(bool forward_direction,
                                                 float* max_scale) const {
  *max_scale = 1.f;
  return true;
}

std::unique_ptr<AnimationCurve> FakeTransformTransition::Clone() const {
  return base::WrapUnique(new FakeTransformTransition(*this));
}

FakeFloatTransition::FakeFloatTransition(double duration, float from, float to)
    : duration_(base::TimeDelta::FromSecondsD(duration)), from_(from), to_(to) {
}

FakeFloatTransition::~FakeFloatTransition() = default;

base::TimeDelta FakeFloatTransition::Duration() const {
  return duration_;
}

float FakeFloatTransition::GetValue(base::TimeDelta time) const {
  const double progress = std::min(time / duration_, 1.0);
  return (1.0 - progress) * from_ + progress * to_;
}

std::unique_ptr<AnimationCurve> FakeFloatTransition::Clone() const {
  return base::WrapUnique(new FakeFloatTransition(*this));
}

int AddScrollOffsetAnimationToAnimation(Animation* animation,
                                        gfx::ScrollOffset initial_value,
                                        gfx::ScrollOffset target_value) {
  std::unique_ptr<ScrollOffsetAnimationCurve> curve(
      ScrollOffsetAnimationCurveFactory::CreateEaseInOutAnimationForTesting(
          target_value));
  curve->SetInitialValue(initial_value);

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::SCROLL_OFFSET));
  keyframe_model->SetIsImplOnly();

  animation->AddKeyframeModel(std::move(keyframe_model));

  return id;
}

int AddAnimatedTransformToAnimation(Animation* animation,
                                    double duration,
                                    int delta_x,
                                    int delta_y) {
  return AddAnimatedTransform(animation, duration, delta_x, delta_y);
}

int AddAnimatedTransformToAnimation(Animation* animation,
                                    double duration,
                                    TransformOperations start_operations,
                                    TransformOperations operations) {
  return AddAnimatedTransform(animation, duration, start_operations,
                              operations);
}

int AddOpacityTransitionToAnimation(Animation* animation,
                                    double duration,
                                    float start_opacity,
                                    float end_opacity,
                                    bool use_timing_function) {
  return AddOpacityTransition(animation, duration, start_opacity, end_opacity,
                              use_timing_function);
}

int AddAnimatedFilterToAnimation(Animation* animation,
                                 double duration,
                                 float start_brightness,
                                 float end_brightness) {
  return AddAnimatedFilter(animation, duration, start_brightness,
                           end_brightness);
}

int AddAnimatedBackdropFilterToAnimation(Animation* animation,
                                         double duration,
                                         float start_invert,
                                         float end_invert) {
  return AddAnimatedBackdropFilter(animation, duration, start_invert,
                                   end_invert);
}

int AddOpacityStepsToAnimation(Animation* animation,
                               double duration,
                               float start_opacity,
                               float end_opacity,
                               int num_steps) {
  std::unique_ptr<KeyframedFloatAnimationCurve> curve(
      KeyframedFloatAnimationCurve::Create());

  std::unique_ptr<TimingFunction> func = StepsTimingFunction::Create(
      num_steps, StepsTimingFunction::StepPosition::START);
  if (duration > 0.0)
    curve->AddKeyframe(FloatKeyframe::Create(base::TimeDelta(), start_opacity,
                                             std::move(func)));
  curve->AddKeyframe(FloatKeyframe::Create(
      base::TimeDelta::FromSecondsD(duration), end_opacity, nullptr));

  int id = AnimationIdProvider::NextKeyframeModelId();

  std::unique_ptr<KeyframeModel> keyframe_model(KeyframeModel::Create(
      std::move(curve), id, AnimationIdProvider::NextGroupId(),
      TargetProperty::OPACITY));
  keyframe_model->set_needs_synchronized_start_time(true);

  animation->AddKeyframeModel(std::move(keyframe_model));
  return id;
}

void AddKeyframeModelToElementWithAnimation(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    std::unique_ptr<KeyframeModel> keyframe_model) {
  scoped_refptr<Animation> animation =
      Animation::Create(AnimationIdProvider::NextAnimationId());
  timeline->AttachAnimation(animation);
  animation->AttachElement(element_id);
  DCHECK(animation->keyframe_effect()->element_animations());
  animation->AddKeyframeModel(std::move(keyframe_model));
}

void AddKeyframeModelToElementWithExistingKeyframeEffect(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    std::unique_ptr<KeyframeModel> keyframe_model) {
  scoped_refptr<ElementAnimations> element_animations =
      timeline->animation_host()->GetElementAnimationsForElementId(element_id);
  DCHECK(element_animations);
  KeyframeEffect* keyframe_effect =
      element_animations->FirstKeyframeEffectForTesting();
  DCHECK(keyframe_effect);
  keyframe_effect->AddKeyframeModel(std::move(keyframe_model));
}

void RemoveKeyframeModelFromElementWithExistingKeyframeEffect(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    int keyframe_model_id) {
  scoped_refptr<ElementAnimations> element_animations =
      timeline->animation_host()->GetElementAnimationsForElementId(element_id);
  DCHECK(element_animations);
  KeyframeEffect* keyframe_effect =
      element_animations->FirstKeyframeEffectForTesting();
  DCHECK(keyframe_effect);
  keyframe_effect->RemoveKeyframeModel(keyframe_model_id);
}

KeyframeModel* GetKeyframeModelFromElementWithExistingKeyframeEffect(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    int keyframe_model_id) {
  scoped_refptr<ElementAnimations> element_animations =
      timeline->animation_host()->GetElementAnimationsForElementId(element_id);
  DCHECK(element_animations);
  KeyframeEffect* keyframe_effect =
      element_animations->FirstKeyframeEffectForTesting();
  DCHECK(keyframe_effect);
  return keyframe_effect->GetKeyframeModelById(keyframe_model_id);
}

int AddAnimatedFilterToElementWithAnimation(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    double duration,
    float start_brightness,
    float end_brightness) {
  scoped_refptr<Animation> animation =
      Animation::Create(AnimationIdProvider::NextAnimationId());
  timeline->AttachAnimation(animation);
  animation->AttachElement(element_id);
  DCHECK(animation->keyframe_effect()->element_animations());
  return AddAnimatedFilterToAnimation(animation.get(), duration,
                                      start_brightness, end_brightness);
}

int AddAnimatedTransformToElementWithAnimation(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    double duration,
    int delta_x,
    int delta_y) {
  scoped_refptr<Animation> animation =
      Animation::Create(AnimationIdProvider::NextAnimationId());
  timeline->AttachAnimation(animation);
  animation->AttachElement(element_id);
  DCHECK(animation->keyframe_effect()->element_animations());
  return AddAnimatedTransformToAnimation(animation.get(), duration, delta_x,
                                         delta_y);
}

int AddAnimatedTransformToElementWithAnimation(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    double duration,
    TransformOperations start_operations,
    TransformOperations operations) {
  scoped_refptr<Animation> animation =
      Animation::Create(AnimationIdProvider::NextAnimationId());
  timeline->AttachAnimation(animation);
  animation->AttachElement(element_id);
  DCHECK(animation->keyframe_effect()->element_animations());
  return AddAnimatedTransformToAnimation(animation.get(), duration,
                                         start_operations, operations);
}

int AddOpacityTransitionToElementWithAnimation(
    ElementId element_id,
    scoped_refptr<AnimationTimeline> timeline,
    double duration,
    float start_opacity,
    float end_opacity,
    bool use_timing_function) {
  scoped_refptr<Animation> animation =
      Animation::Create(AnimationIdProvider::NextAnimationId());
  timeline->AttachAnimation(animation);
  animation->AttachElement(element_id);
  DCHECK(animation->keyframe_effect()->element_animations());
  return AddOpacityTransitionToAnimation(animation.get(), duration,
                                         start_opacity, end_opacity,
                                         use_timing_function);
}

}  // namespace cc
