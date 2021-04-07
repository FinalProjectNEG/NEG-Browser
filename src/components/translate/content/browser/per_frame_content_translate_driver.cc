// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/translate/content/browser/per_frame_content_translate_driver.h"

#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/feature_list.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/utf_string_conversions.h"
#include "base/supports_user_data.h"
#include "base/threading/thread_task_runner_handle.h"
#include "components/google/core/common/google_util.h"
#include "components/language/core/browser/url_language_histogram.h"
#include "components/translate/content/browser/content_record_page_language.h"
#include "components/translate/content/browser/content_translate_util.h"
#include "components/translate/core/browser/translate_browser_metrics.h"
#include "components/translate/core/browser/translate_download_manager.h"
#include "components/translate/core/browser/translate_manager.h"
#include "components/translate/core/common/translate_metrics.h"
#include "components/translate/core/common/translate_util.h"
#include "components/translate/core/language_detection/language_detection_util.h"
#include "components/ukm/content/source_url_recorder.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/navigation_details.h"
#include "content/public/browser/navigation_entry.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/page_navigator.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/referrer.h"
#include "net/http/http_status_code.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "third_party/blink/public/common/associated_interfaces/associated_interface_provider.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "ui/accessibility/ax_node.h"
#include "ui/accessibility/ax_tree.h"
#include "url/gurl.h"

namespace translate {

namespace {

// Constants for UMA statistic collection.
static const char kTranslateCaptureText[] = "Translate.CaptureText";
static const char kTranslateFrameCount[] = "Translate.TranslateFrameCount";
static const char kTranslateSubframeSuccessPercentage[] =
    "Translate.TranslateSubframe.SuccessPercentage";
static const char kTranslateSubframeErrorType[] =
    "Translate.TranslateSubframe.ErrorType";

// A helper function for CombineTextNodesAndMakeCallback() below.
// This is a copy of logic from macos specific RenderWidgetHostViewMac
// that was created in https://chromium-review.googlesource.com/956029
// TODO(dougarnett): Factor this out into a utility class that can be
// shared here and with the original macos copy.
void AddTextNodesToVector(const ui::AXNode* node,
                          std::vector<base::string16>* strings) {
  const ui::AXNodeData& node_data = node->data();

  if (node_data.role == ax::mojom::Role::kStaticText) {
    if (node_data.HasStringAttribute(ax::mojom::StringAttribute::kName)) {
      strings->emplace_back(
          node_data.GetString16Attribute(ax::mojom::StringAttribute::kName));
    }
    return;
  }

  for (const auto* child : node->children())
    AddTextNodesToVector(child, strings);
}

using PageContentsCallback = base::OnceCallback<void(const base::string16&)>;
void CombineTextNodesAndMakeCallback(PageContentsCallback callback,
                                     const ui::AXTreeUpdate& update) {
  ui::AXTree tree;
  if (!tree.Unserialize(update)) {
    std::move(callback).Run(base::ASCIIToUTF16(""));
    return;
  }

  std::vector<base::string16> text_node_contents;
  text_node_contents.reserve(update.nodes.size());

  AddTextNodesToVector(tree.root(), &text_node_contents);

  std::move(callback).Run(
      base::JoinString(text_node_contents, base::ASCIIToUTF16("\n")));
}
}  // namespace

PerFrameContentTranslateDriver::PendingRequestStats::PendingRequestStats() =
    default;
PerFrameContentTranslateDriver::PendingRequestStats::~PendingRequestStats() =
    default;

void PerFrameContentTranslateDriver::PendingRequestStats::Clear() {
  pending_request_count = 0;
  main_frame_success = false;
  main_frame_error = TranslateErrors::NONE;
  frame_request_count = 0;
  frame_success_count = 0;
  frame_errors.clear();
}

void PerFrameContentTranslateDriver::PendingRequestStats::Report() {
  UMA_HISTOGRAM_COUNTS_100(kTranslateFrameCount, frame_request_count);
  if (main_frame_success) {
    if (frame_request_count > 1) {
      int success_percentage_as_int =
          (frame_success_count * 100) / frame_request_count;
      UMA_HISTOGRAM_PERCENTAGE(kTranslateSubframeSuccessPercentage,
                               success_percentage_as_int);
    }
    for (TranslateErrors::Type error_type : frame_errors) {
      UMA_HISTOGRAM_ENUMERATION(kTranslateSubframeErrorType, error_type,
                                TranslateErrors::TRANSLATE_ERROR_MAX);
    }
  }
}

PerFrameContentTranslateDriver::PerFrameContentTranslateDriver(
    content::NavigationController* nav_controller,
    language::UrlLanguageHistogram* url_language_histogram)
    : ContentTranslateDriver(nav_controller, url_language_histogram) {}

PerFrameContentTranslateDriver::~PerFrameContentTranslateDriver() = default;

// TranslateDriver methods

void PerFrameContentTranslateDriver::TranslatePage(
    int page_seq_no,
    const std::string& translate_script,
    const std::string& source_lang,
    const std::string& target_lang) {
  if (!IsForCurrentPage(page_seq_no))
    return;

  ReportUserActionDuration(language_determined_time_, base::TimeTicks::Now());
  stats_.Clear();
  translate_seq_no_ = IncrementSeqNo(translate_seq_no_);

  web_contents()->ForEachFrame(base::BindRepeating(
      &PerFrameContentTranslateDriver::TranslateFrame, base::Unretained(this),
      translate_script, source_lang, target_lang, translate_seq_no_));
}

void PerFrameContentTranslateDriver::TranslateFrame(
    const std::string& translate_script,
    const std::string& source_lang,
    const std::string& target_lang,
    int translate_seq_no,
    content::RenderFrameHost* render_frame_host) {
  if (render_frame_host->IsFrameDisplayNone() ||
      !translate::IsTranslatableURL(render_frame_host->GetLastCommittedURL())) {
    return;
  }

  bool is_main_frame = (!render_frame_host->GetParent());
  mojo::AssociatedRemote<mojom::TranslateAgent> frame_agent;
  render_frame_host->GetRemoteAssociatedInterfaces()->GetInterface(
      &frame_agent);
  mojom::TranslateAgent* frame_agent_ptr = frame_agent.get();
  frame_agent_ptr->TranslateFrame(
      translate_script, source_lang, target_lang,
      base::BindOnce(&PerFrameContentTranslateDriver::OnFrameTranslated,
                     weak_pointer_factory_.GetWeakPtr(), translate_seq_no,
                     is_main_frame, std::move(frame_agent)));
  stats_.frame_request_count++;
  stats_.pending_request_count++;
}

void PerFrameContentTranslateDriver::RevertTranslation(int page_seq_no) {
  if (!IsForCurrentPage(page_seq_no))
    return;

  stats_.Clear();
  translate_seq_no_ = IncrementSeqNo(translate_seq_no_);

  web_contents()->ForEachFrame(base::BindRepeating(
      &PerFrameContentTranslateDriver::RevertFrame, base::Unretained(this)));
}

void PerFrameContentTranslateDriver::RevertFrame(
    content::RenderFrameHost* render_frame_host) {
  if (render_frame_host->IsFrameDisplayNone() ||
      !translate::IsTranslatableURL(render_frame_host->GetLastCommittedURL())) {
    return;
  }

    mojo::AssociatedRemote<mojom::TranslateAgent> frame_agent;
    render_frame_host->GetRemoteAssociatedInterfaces()->GetInterface(
        &frame_agent);
    frame_agent->RevertTranslation();
}

// content::WebContentsObserver methods
void PerFrameContentTranslateDriver::NavigationEntryCommitted(
    const content::LoadCommittedDetails& load_details) {
  // Check whether this is a reload: When doing a page reload, the
  // TranslateLanguageDetermined IPC is not sent so the translation needs to be
  // explicitly initiated.

  content::NavigationEntry* entry =
      web_contents()->GetController().GetLastCommittedEntry();
  if (!entry) {
    NOTREACHED();
    return;
  }

  // If the navigation happened while offline don't show the translate
  // bar since there will be nothing to translate.
  if (load_details.http_status_code == 0 ||
      load_details.http_status_code == net::HTTP_INTERNAL_SERVER_ERROR) {
    return;
  }

  if (!load_details.is_main_frame &&
      translate_manager()->GetLanguageState()->translation_declined()) {
    // Some sites (such as Google map) may trigger sub-frame navigations
    // when the user interacts with the page.  We don't want to show a new
    // infobar if the user already dismissed one in that case.
    return;
  }

  // If not a reload, return.
  if (!ui::PageTransitionCoreTypeIs(entry->GetTransitionType(),
                                    ui::PAGE_TRANSITION_RELOAD) &&
      load_details.type != content::NAVIGATION_TYPE_SAME_PAGE) {
    return;
  }

  if (entry->GetTransitionType() & ui::PAGE_TRANSITION_FORWARD_BACK) {
    // Workaround for http://crbug.com/653051: back navigation sometimes have
    // the reload core type. Once http://crbug.com/669008 got resolved, we
    // could revisit here for a thorough solution.
    //
    // This means that the new translation won't be started when the page
    // is restored from back-forward cache, which is the right thing to do.
    // TODO(crbug.com/1001087): Ensure that it stays disabled for
    // back-forward navigations even when bug above is fixed.
    return;
  }

  if (!translate_manager()->GetLanguageState()->page_needs_translation())
    return;

  // Note that we delay it as the ordering of the processing of this callback
  // by WebContentsObservers is undefined and might result in the current
  // infobars being removed. Since the translation initiation process might add
  // an infobar, it must be done after that.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &PerFrameContentTranslateDriver::InitiateTranslation,
          weak_pointer_factory_.GetWeakPtr(),
          translate_manager()->GetLanguageState()->original_language(), 0));
}

void PerFrameContentTranslateDriver::DidFinishNavigation(
    content::NavigationHandle* navigation_handle) {
  if (!navigation_handle->HasCommitted())
    return;

  if (navigation_handle->IsInMainFrame())
    finish_navigation_time_ = base::TimeTicks::Now();

  // Let the LanguageState clear its state.
  const bool reload =
      navigation_handle->GetReloadType() != content::ReloadType::NONE ||
      navigation_handle->IsSameDocument();

  const base::Optional<url::Origin>& initiator_origin =
      navigation_handle->GetInitiatorOrigin();

  bool navigation_from_google =
      initiator_origin.has_value() &&
      (google_util::IsGoogleDomainUrl(initiator_origin->GetURL(),
                                      google_util::DISALLOW_SUBDOMAIN,
                                      google_util::ALLOW_NON_STANDARD_PORTS) ||
       IsAutoHrefTranslateAllOriginsEnabled());

  translate_manager()->GetLanguageState()->DidNavigate(
      navigation_handle->IsSameDocument(), navigation_handle->IsInMainFrame(),
      reload, navigation_handle->GetHrefTranslate(), navigation_from_google);
}

void PerFrameContentTranslateDriver::DOMContentLoaded(
    content::RenderFrameHost* render_frame_host) {
  if (render_frame_host->GetParent()) {
    // Nothing to do for sub frames here.
    return;
  }

  // Main frame loaded, set new sequence number.
  page_seq_no_ = IncrementSeqNo(page_seq_no_);
  translate_manager()->set_current_seq_no(page_seq_no_);

  // Start language detection now if not waiting for sub frames
  // to load to use for detection.
  if (!translate::IsSubFrameLanguageDetectionEnabled() &&
      translate::IsTranslatableURL(web_contents()->GetURL())) {
    StartLanguageDetection();
  }
}

void PerFrameContentTranslateDriver::DocumentOnLoadCompletedInMainFrame() {
  if (translate::IsSubFrameLanguageDetectionEnabled() &&
      translate::IsTranslatableURL(web_contents()->GetURL())) {
    StartLanguageDetection();
  }
}

void PerFrameContentTranslateDriver::StartLanguageDetection() {
  // Get page contents (via snapshot of a11y tree) for language determination.
  // This will include subframe content for any subframes loaded at this point.
  base::TimeTicks capture_begin_time = base::TimeTicks::Now();
  awaiting_contents_ = true;
  web_contents()->RequestAXTreeSnapshot(
      base::BindOnce(
          CombineTextNodesAndMakeCallback,
          base::BindOnce(&PerFrameContentTranslateDriver::OnPageContents,
                         weak_pointer_factory_.GetWeakPtr(),
                         capture_begin_time)),
      ui::AXMode::kWebContents);

  // Kick off language detection by first requesting web language details.
  details_ = LanguageDetectionDetails();
  mojo::AssociatedRemote<mojom::TranslateAgent> frame_agent;
  web_contents()->GetMainFrame()->GetRemoteAssociatedInterfaces()->GetInterface(
      &frame_agent);
  mojom::TranslateAgent* frame_agent_ptr = frame_agent.get();
  frame_agent_ptr->GetWebLanguageDetectionDetails(base::BindOnce(
      &PerFrameContentTranslateDriver::OnWebLanguageDetectionDetails,
      weak_pointer_factory_.GetWeakPtr(), std::move(frame_agent)));
}

void PerFrameContentTranslateDriver::OnPageLanguageDetermined(
    const LanguageDetectionDetails& details,
    bool page_needs_translation) {
  language_determined_time_ = base::TimeTicks::Now();
  ReportLanguageDeterminedDuration(finish_navigation_time_,
                                   language_determined_time_);

  // If we have a language histogram (i.e. we're not in incognito), update it
  // with the detected language of every page visited.
  if (language_histogram() && details.is_cld_reliable)
    language_histogram()->OnPageVisited(details.cld_language);

  if (translate_manager() && web_contents()) {
    translate_manager()->GetLanguageState()->LanguageDetermined(
        details.adopted_language, page_needs_translation);
    translate_manager()->InitiateTranslation(details.adopted_language);
  }

  for (auto& observer : observer_list())
    observer.OnLanguageDetermined(details);
}

void PerFrameContentTranslateDriver::OnWebLanguageDetectionDetails(
    mojo::AssociatedRemote<mojom::TranslateAgent> translate_agent,
    const std::string& content_language,
    const std::string& html_lang,
    const GURL& url,
    bool has_notranslate_meta) {
  details_.content_language = content_language;
  details_.html_root_language = html_lang;
  details_.url = url;
  details_.has_notranslate = has_notranslate_meta;

  if (!awaiting_contents_)
    ComputeActualPageLanguage();
}

void PerFrameContentTranslateDriver::OnPageContents(
    base::TimeTicks capture_begin_time,
    const base::string16& contents) {
  details_.contents = contents;
  UMA_HISTOGRAM_TIMES(kTranslateCaptureText,
                      base::TimeTicks::Now() - capture_begin_time);

  // Run language detection of contents in a sandboxed utility process.
  mojo::Remote<language_detection::mojom::LanguageDetectionService> service =
      language_detection::LaunchLanguageDetectionService();
  // Ensure that we call `service.get()` _before_ moving out of `service` below.
  auto* raw_service = service.get();
  raw_service->DetermineLanguage(
      contents,
      base::BindOnce(&PerFrameContentTranslateDriver::OnPageContentsLanguage,
                     weak_pointer_factory_.GetWeakPtr(), std::move(service)));
}

void PerFrameContentTranslateDriver::OnPageContentsLanguage(
    mojo::Remote<language_detection::mojom::LanguageDetectionService>
        service_handle,
    const std::string& contents_language,
    bool is_contents_language_reliable) {
  awaiting_contents_ = false;
  details_.cld_language = contents_language;
  details_.is_cld_reliable = is_contents_language_reliable;

  if (!details_.url.is_empty())
    ComputeActualPageLanguage();
}

void PerFrameContentTranslateDriver::ComputeActualPageLanguage() {
  // TODO(crbug.com/1063520): Move this language detection to a sandboxed
  // utility process.
  std::string language = DeterminePageLanguage(
      details_.content_language, details_.html_root_language,
      details_.cld_language, details_.is_cld_reliable);

  if (!language.empty()) {
    details_.time = base::Time::Now();
    details_.adopted_language = language;

    OnPageLanguageDetermined(details_,
                             !details_.has_notranslate && !language.empty());
  }
  details_ = LanguageDetectionDetails();
}

void PerFrameContentTranslateDriver::OnFrameTranslated(
    int translate_seq_no,
    bool is_main_frame,
    mojo::AssociatedRemote<mojom::TranslateAgent> translate_agent,
    bool cancelled,
    const std::string& original_lang,
    const std::string& translated_lang,
    TranslateErrors::Type error_type) {
  if (cancelled)
    return;

  if (translate_seq_no != translate_seq_no_)
    return;

  if (error_type == TranslateErrors::NONE) {
    stats_.frame_success_count++;
    if (is_main_frame) {
      stats_.main_frame_success = true;
    }
  } else {
    stats_.frame_errors.push_back(error_type);
    if (is_main_frame) {
      stats_.main_frame_error = error_type;
    }
  }

  if (--stats_.pending_request_count == 0) {
    // Post the callback on the thread's task runner in case the
    // info bar is in the process of going away.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(&ContentTranslateDriver::OnPageTranslated,
                                  weak_pointer_factory_.GetWeakPtr(), cancelled,
                                  original_lang, translated_lang,
                                  stats_.main_frame_error));
    stats_.Report();
    stats_.Clear();
  }
}

bool PerFrameContentTranslateDriver::IsForCurrentPage(int page_seq_no) {
  return page_seq_no > 0 && page_seq_no == page_seq_no_;
}

}  // namespace translate
