// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SHARE_QR_CODE_GENERATION_REQUEST_H_
#define CHROME_BROWSER_SHARE_QR_CODE_GENERATION_REQUEST_H_

#include <jni.h>

#include "base/android/jni_android.h"
#include "base/android/scoped_java_ref.h"
#include "base/macros.h"
#include "chrome/services/qrcode_generator/public/cpp/qrcode_generator_service.h"
#include "ui/gfx/android/java_bitmap.h"

// A wrapper class exposing the QR Code Mojo service to Java.
class QRCodeGenerationRequest {
 public:
  QRCodeGenerationRequest(
      JNIEnv* env,
      const base::android::JavaParamRef<jobject>& j_caller,
      const base::android::JavaParamRef<jstring>& j_data_string);
  void Destroy(JNIEnv* env);

 private:
  virtual ~QRCodeGenerationRequest();

  void OnGenerateCodeResponse(
      const qrcode_generator::mojom::GenerateQRCodeResponsePtr
          service_response);

  // Reference to Java QRCodeGenerationRequest containing a callback method.
  base::android::ScopedJavaGlobalRef<jobject> java_qr_code_generation_request_;

  mojo::Remote<qrcode_generator::mojom::QRCodeGeneratorService> remote_;

  DISALLOW_COPY_AND_ASSIGN(QRCodeGenerationRequest);
};

#endif  // CHROME_BROWSER_SHARE_QR_CODE_GENERATION_REQUEST_H_
