// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/android/device_dialog/usb_chooser_dialog_android.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "base/android/jni_android.h"
#include "base/android/jni_string.h"
#include "base/bind.h"
#include "base/strings/utf_string_conversions.h"
#include "chrome/android/chrome_jni_headers/UsbChooserDialog_jni.h"
#include "chrome/browser/ssl/security_state_tab_helper.h"
#include "chrome/browser/vr/vr_tab_helper.h"
#include "chrome/common/url_constants.h"
#include "components/security_state/core/security_state.h"
#include "components/url_formatter/elide_url.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "device/vr/buildflags/buildflags.h"
#include "ui/android/window_android.h"
#include "url/gurl.h"

// static
std::unique_ptr<UsbChooserDialogAndroid> UsbChooserDialogAndroid::Create(
    content::RenderFrameHost* render_frame_host,
    std::unique_ptr<ChooserController> controller,
    base::OnceClosure on_close) {
  content::WebContents* web_contents =
      content::WebContents::FromRenderFrameHost(render_frame_host);

  // TODO(asimjour): This should be removed once we have proper
  // implementation of USB chooser in VR.
  if (vr::VrTabHelper::IsUiSuppressedInVr(
          web_contents, vr::UiSuppressedElement::kUsbChooser)) {
    return nullptr;
  }

  // Create (and show) the UsbChooser dialog.
  base::android::ScopedJavaLocalRef<jobject> window_android =
      web_contents->GetNativeView()->GetWindowAndroid()->GetJavaObject();
  JNIEnv* env = base::android::AttachCurrentThread();
  base::android::ScopedJavaLocalRef<jstring> origin_string =
      base::android::ConvertUTF16ToJavaString(
          env, url_formatter::FormatOriginForSecurityDisplay(
                   render_frame_host->GetLastCommittedOrigin()));
  SecurityStateTabHelper* helper =
      SecurityStateTabHelper::FromWebContents(web_contents);
  DCHECK(helper);

  auto dialog = std::make_unique<UsbChooserDialogAndroid>(std::move(controller),
                                                          std::move(on_close));
  dialog->java_dialog_.Reset(Java_UsbChooserDialog_create(
      env, window_android, origin_string, helper->GetSecurityLevel(),
      reinterpret_cast<intptr_t>(dialog.get())));
  if (dialog->java_dialog_.is_null())
    return nullptr;

  return dialog;
}

UsbChooserDialogAndroid::UsbChooserDialogAndroid(
    std::unique_ptr<ChooserController> controller,
    base::OnceClosure on_close)
    : controller_(std::move(controller)), on_close_(std::move(on_close)) {
  controller_->set_view(this);
}

UsbChooserDialogAndroid::~UsbChooserDialogAndroid() {
  if (!java_dialog_.is_null()) {
    Java_UsbChooserDialog_closeDialog(base::android::AttachCurrentThread(),
                                      java_dialog_);
  }
  controller_->set_view(nullptr);
}

void UsbChooserDialogAndroid::OnOptionsInitialized() {
  for (size_t i = 0; i < controller_->NumOptions(); ++i)
    OnOptionAdded(i);

  JNIEnv* env = base::android::AttachCurrentThread();
  Java_UsbChooserDialog_setIdleState(env, java_dialog_);
}

void UsbChooserDialogAndroid::OnOptionAdded(size_t index) {
  JNIEnv* env = base::android::AttachCurrentThread();

  DCHECK_LE(index, item_id_map_.size());
  int item_id = next_item_id_++;
  std::string item_id_str = base::NumberToString(item_id);
  item_id_map_.insert(item_id_map_.begin() + index, item_id_str);

  base::string16 device_name = controller_->GetOption(index);
  Java_UsbChooserDialog_addDevice(
      env, java_dialog_,
      base::android::ConvertUTF8ToJavaString(env, item_id_str),
      base::android::ConvertUTF16ToJavaString(env, device_name));
}

void UsbChooserDialogAndroid::OnOptionRemoved(size_t index) {
  JNIEnv* env = base::android::AttachCurrentThread();

  DCHECK_LT(index, item_id_map_.size());
  std::string item_id = item_id_map_[index];
  item_id_map_.erase(item_id_map_.begin() + index);

  Java_UsbChooserDialog_removeDevice(
      env, java_dialog_, base::android::ConvertUTF8ToJavaString(env, item_id));
}

void UsbChooserDialogAndroid::OnOptionUpdated(size_t index) {
  NOTREACHED();
}

void UsbChooserDialogAndroid::OnAdapterEnabledChanged(bool enabled) {
  NOTREACHED();
}

void UsbChooserDialogAndroid::OnRefreshStateChanged(bool refreshing) {
  NOTREACHED();
}

void UsbChooserDialogAndroid::OnItemSelected(
    JNIEnv* env,
    const base::android::JavaParamRef<jstring>& item_id_jstring) {
  std::string item_id =
      base::android::ConvertJavaStringToUTF8(env, item_id_jstring);
  auto it = std::find(item_id_map_.begin(), item_id_map_.end(), item_id);
  DCHECK(it != item_id_map_.end());
  controller_->Select({std::distance(item_id_map_.begin(), it)});
  std::move(on_close_).Run();
}

void UsbChooserDialogAndroid::OnDialogCancelled(JNIEnv* env) {
  Cancel();
}

void UsbChooserDialogAndroid::LoadUsbHelpPage(JNIEnv* env) {
  controller_->OpenHelpCenterUrl();
  Cancel();
}

void UsbChooserDialogAndroid::Cancel() {
  controller_->Cancel();
  std::move(on_close_).Run();
}
