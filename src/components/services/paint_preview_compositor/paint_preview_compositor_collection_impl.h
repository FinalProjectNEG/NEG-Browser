// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_SERVICES_PAINT_PREVIEW_COMPOSITOR_PAINT_PREVIEW_COMPOSITOR_COLLECTION_IMPL_H_
#define COMPONENTS_SERVICES_PAINT_PREVIEW_COMPOSITOR_PAINT_PREVIEW_COMPOSITOR_COLLECTION_IMPL_H_

#include <memory>

#include "base/callback.h"
#include "base/containers/flat_map.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "components/discardable_memory/client/client_discardable_shared_memory_manager.h"
#include "components/services/paint_preview_compositor/paint_preview_compositor_impl.h"
#include "components/services/paint_preview_compositor/public/mojom/paint_preview_compositor.mojom.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/receiver.h"

#if defined(OS_LINUX) || defined(OS_CHROMEOS)
#include "components/services/font/public/cpp/font_loader.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#endif

namespace discardable_memory {
class ClientDiscardableSharedMemoryManager;
}

namespace paint_preview {

class PaintPreviewCompositorCollectionImpl
    : public mojom::PaintPreviewCompositorCollection {
 public:
  // Create a new PaintPreviewCompositorCollectionImpl bound to |receiver| (can
  // be nullptr for tests). Will attempt to initialize required font access if
  // |initialize_environment| is true. |io_task_runner| is used by the
  // discardable memory manager client for operations on shared memory.
  PaintPreviewCompositorCollectionImpl(
      mojo::PendingReceiver<mojom::PaintPreviewCompositorCollection> receiver,
      bool initialize_environment,
      scoped_refptr<base::SingleThreadTaskRunner> io_task_runner);
  ~PaintPreviewCompositorCollectionImpl() override;

  PaintPreviewCompositorCollectionImpl(
      const PaintPreviewCompositorCollectionImpl&) = delete;
  PaintPreviewCompositorCollectionImpl& operator=(
      const PaintPreviewCompositorCollectionImpl&) = delete;

  // PaintPreviewCompositorCollection implementation.
  void SetDiscardableSharedMemoryManager(
      mojo::PendingRemote<
          discardable_memory::mojom::DiscardableSharedMemoryManager> manager)
      override;
  void CreateCompositor(
      mojo::PendingReceiver<mojom::PaintPreviewCompositor> compositor,
      CreateCompositorCallback callback) override;
  void ListCompositors(ListCompositorsCallback callback) override;

 private:
  // Invoked by a |compositor| when it is disconnected from its remote. Used to
  // delete the corresponding instance from |compositors_|.
  void OnDisconnect(const base::UnguessableToken& id);

  mojo::Receiver<mojom::PaintPreviewCompositorCollection> receiver_{this};

  const scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  std::unique_ptr<discardable_memory::ClientDiscardableSharedMemoryManager>
      discardable_shared_memory_manager_;

  base::flat_map<base::UnguessableToken,
                 std::unique_ptr<PaintPreviewCompositorImpl>>
      compositors_;

#if defined(OS_LINUX) || defined(OS_CHROMEOS)
  sk_sp<font_service::FontLoader> font_loader_;
#endif

  base::WeakPtrFactory<PaintPreviewCompositorCollectionImpl> weak_ptr_factory_{
      this};
};

}  // namespace paint_preview

#endif  // COMPONENTS_SERVICES_PAINT_PREVIEW_COMPOSITOR_PAINT_PREVIEW_COMPOSITOR_COLLECTION_IMPL_H_
