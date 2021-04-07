// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/prerender/renderer/prerender_observer_list.h"

#include "components/prerender/renderer/prerender_observer.h"
#include "content/public/renderer/render_frame.h"

namespace prerender {

namespace {

// Key used to attach the handler to the RenderFrame.
const char kPrerenderObserverListKey[] = "kPrerenderObserverListKey";

}  // namespace

// static
void PrerenderObserverList::AddObserverForFrame(
    content::RenderFrame* render_frame,
    PrerenderObserver* observer) {
  auto* observer_list = static_cast<PrerenderObserverList*>(
      render_frame->GetUserData(kPrerenderObserverListKey));
  if (!observer_list) {
    observer_list = new PrerenderObserverList();
    render_frame->SetUserData(kPrerenderObserverListKey,
                              base::WrapUnique(observer_list));
  }

  observer_list->AddObserver(observer);
}

// static
void PrerenderObserverList::RemoveObserverForFrame(
    content::RenderFrame* render_frame,
    PrerenderObserver* observer) {
  auto* observer_list = static_cast<PrerenderObserverList*>(
      render_frame->GetUserData(kPrerenderObserverListKey));
  DCHECK(observer_list);

  // Delete the PrerenderObserverList instance when the last observer is
  // removed.
  if (observer_list->RemoveObserver(observer))
    render_frame->RemoveUserData(kPrerenderObserverListKey);
}

// static
void PrerenderObserverList::SetIsPrerenderingForFrame(
    content::RenderFrame* render_frame,
    bool is_prerendering) {
  auto* observer_list = static_cast<PrerenderObserverList*>(
      render_frame->GetUserData(kPrerenderObserverListKey));
  if (observer_list)
    observer_list->SetIsPrerendering(is_prerendering);
}

PrerenderObserverList::PrerenderObserverList() = default;
PrerenderObserverList::~PrerenderObserverList() = default;

void PrerenderObserverList::AddObserver(PrerenderObserver* observer) {
  prerender_observers_.AddObserver(observer);
}

bool PrerenderObserverList::RemoveObserver(PrerenderObserver* observer) {
  prerender_observers_.RemoveObserver(observer);
  return !prerender_observers_.might_have_observers();
}

void PrerenderObserverList::SetIsPrerendering(bool is_prerendering) {
  for (auto& observer : prerender_observers_)
    observer.SetIsPrerendering(is_prerendering);
}

}  // namespace prerender
