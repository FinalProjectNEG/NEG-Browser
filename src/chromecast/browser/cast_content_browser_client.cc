// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromecast/browser/cast_content_browser_client.h"

#include <stddef.h>

#include <utility>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/files/scoped_file.h"
#include "base/i18n/rtl.h"
#include "base/message_loop/message_pump_type.h"
#include "base/metrics/ukm_source_id.h"
#include "base/path_service.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "chromecast/base/cast_constants.h"
#include "chromecast/base/cast_features.h"
#include "chromecast/base/cast_paths.h"
#include "chromecast/base/chromecast_switches.h"
#include "chromecast/base/pref_names.h"
#include "chromecast/browser/application_media_info_manager.h"
#include "chromecast/browser/browser_buildflags.h"
#include "chromecast/browser/cast_browser_context.h"
#include "chromecast/browser/cast_browser_main_parts.h"
#include "chromecast/browser/cast_browser_process.h"
#include "chromecast/browser/cast_feature_list_creator.h"
#include "chromecast/browser/cast_http_user_agent_settings.h"
#include "chromecast/browser/cast_navigation_ui_data.h"
#include "chromecast/browser/cast_network_contexts.h"
#include "chromecast/browser/cast_overlay_manifests.h"
#include "chromecast/browser/cast_quota_permission_context.h"
#include "chromecast/browser/cast_session_id_map.h"
#include "chromecast/browser/cast_web_contents.h"
#include "chromecast/browser/cast_web_preferences.h"
#include "chromecast/browser/default_navigation_throttle.h"
#include "chromecast/browser/devtools/cast_devtools_manager_delegate.h"
#include "chromecast/browser/general_audience_browsing_navigation_throttle.h"
#include "chromecast/browser/general_audience_browsing_service.h"
#include "chromecast/browser/media/media_caps_impl.h"
#include "chromecast/browser/service/cast_service_simple.h"
#include "chromecast/browser/service_connector.h"
#include "chromecast/common/cast_content_client.h"
#include "chromecast/common/global_descriptors.h"
#include "chromecast/media/audio/cast_audio_manager.h"
#include "chromecast/media/base/media_resource_tracker.h"
#include "chromecast/media/cdm/cast_cdm_factory.h"
#include "chromecast/media/cdm/cast_cdm_origin_provider.h"
#include "chromecast/media/cma/backend/cma_backend_factory_impl.h"
#include "chromecast/media/cma/backend/media_pipeline_backend_manager.h"
#include "chromecast/media/service/cast_renderer.h"
#include "chromecast/media/service/mojom/video_geometry_setter.mojom.h"
#include "chromecast/public/media/media_pipeline_backend.h"
#include "components/prefs/pref_service.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/certificate_request_result_type.h"
#include "content/public/browser/client_certificate_delegate.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/navigation_ui_data.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/site_instance.h"
#include "content/public/browser/storage_partition.h"
#include "content/public/browser/system_connector.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_ui_url_loader_factory.h"
#include "content/public/common/content_descriptors.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/service_names.mojom.h"
#include "content/public/common/url_constants.h"
#include "media/audio/audio_thread_impl.h"
#include "media/base/media_switches.h"
#include "media/mojo/services/mojo_renderer_service.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/public/cpp/network_switches.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/gl/gl_switches.h"

#if defined(OS_LINUX) || defined(OS_CHROMEOS) || defined(OS_ANDROID)
#include "components/crash/content/browser/crash_handler_host_linux.h"
#endif  // defined(OS_LINUX) || defined(OS_CHROMEOS) || defined(OS_ANDROID)

#if defined(OS_LINUX) || defined(OS_CHROMEOS)
#include "components/crash/core/app/breakpad_linux.h"
#endif  // defined(OS_LINUX) || defined(OS_CHROMEOS)

#if defined(OS_ANDROID)
#include "chromecast/media/audio/cast_audio_manager_android.h"  // nogncheck
#include "components/cdm/browser/cdm_message_filter_android.h"
#include "components/crash/core/app/crashpad.h"
#include "media/audio/android/audio_manager_android.h"
#else
#include "chromecast/browser/memory_pressure_controller_impl.h"
#endif  // defined(OS_ANDROID)

#if defined(USE_ALSA)
#include "chromecast/media/audio/cast_audio_manager_alsa.h"  // nogncheck
#endif  // defined(USE_ALSA)

#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
#include "chromecast/browser/cast_extension_message_filter.h"      // nogncheck
#include "chromecast/browser/cast_extension_url_loader_factory.h"  // nogncheck
#include "extensions/browser/extension_message_filter.h"           // nogncheck
#include "extensions/browser/extension_protocols.h"                // nogncheck
#include "extensions/browser/extension_registry.h"                 // nogncheck
#include "extensions/browser/guest_view/extensions_guest_view_message_filter.h"  // nogncheck
#include "extensions/browser/guest_view/web_view/web_view_guest.h"  // nogncheck
#include "extensions/browser/process_map.h"                         // nogncheck
#include "extensions/common/constants.h"                            // nogncheck
#endif

#if BUILDFLAG(ENABLE_EXTERNAL_MOJO_SERVICES)
#include "chromecast/external_mojo/broker_service/broker_service.h"
#endif

#if (defined(OS_LINUX) || defined(OS_CHROMEOS)) && defined(USE_OZONE)
#include "chromecast/browser/webview/webview_controller.h"
#endif  // (defined(OS_LINUX) || defined(OS_CHROMEOS)) && defined(USE_OZONE)

#if BUILDFLAG(ENABLE_CAST_RENDERER)
#include "base/sequenced_task_runner.h"
#include "chromecast/media/service/video_geometry_setter_service.h"
#endif  // BUILDFLAG(ENABLE_CAST_RENDERER)

#if !defined(OS_ANDROID) && !defined(OS_FUCHSIA)
#include "device/bluetooth/cast/bluetooth_adapter_cast.h"
#endif

namespace chromecast {
namespace shell {

CastContentBrowserClient::CastContentBrowserClient(
    CastFeatureListCreator* cast_feature_list_creator)
    :
#if BUILDFLAG(ENABLE_CAST_RENDERER)
      video_geometry_setter_service_(
          std::unique_ptr<media::VideoGeometrySetterService,
                          base::OnTaskRunnerDeleter>(
              nullptr,
              base::OnTaskRunnerDeleter(nullptr))),
#endif  // BUILDFLAG(ENABLE_CAST_RENDERER)
      cast_browser_main_parts_(nullptr),
      cast_network_contexts_(
          std::make_unique<CastNetworkContexts>(GetCorsExemptHeadersList())),
      cast_feature_list_creator_(cast_feature_list_creator) {
  cast_feature_list_creator_->SetExtraEnableFeatures({
    ::media::kInternalMediaSession, features::kNetworkServiceInProcess,
        // TODO(b/161486194): Can be removed when it's enabled by default in
        // Chrome.
        features::kWebAssemblySimd,
#if defined(OS_ANDROID) && BUILDFLAG(ENABLE_VIDEO_CAPTURE_SERVICE)
        features::kMojoVideoCapture,
#endif
  });

  cast_feature_list_creator_->SetExtraDisableFeatures({
      // TODO(juke): Reenable this after solving casting issue on LAN.
      blink::features::kMixedContentAutoupgrade,
#if defined(OS_ANDROID)
      ::media::kAudioFocusLossSuspendMediaSession,
      ::media::kRequestSystemAudioFocus,
#endif
  });
}

CastContentBrowserClient::~CastContentBrowserClient() {
  DCHECK(!media_resource_tracker_)
      << "ResetMediaResourceTracker was not called";
  cast_network_contexts_.reset();
}

std::unique_ptr<ServiceConnector>
CastContentBrowserClient::CreateServiceConnector() {
  return std::make_unique<ServiceConnector>();
}

std::unique_ptr<CastService> CastContentBrowserClient::CreateCastService(
    content::BrowserContext* browser_context,
    CastSystemMemoryPressureEvaluatorAdjuster*
        cast_system_memory_pressure_evaluator_adjuster,
    PrefService* pref_service,
    media::VideoPlaneController* video_plane_controller,
    CastWindowManager* window_manager) {
  return std::make_unique<CastServiceSimple>(browser_context, pref_service,
                                             window_manager);
}

media::VideoModeSwitcher* CastContentBrowserClient::GetVideoModeSwitcher() {
  return nullptr;
}

void CastContentBrowserClient::InitializeURLLoaderThrottleDelegate() {}

scoped_refptr<base::SingleThreadTaskRunner>
CastContentBrowserClient::GetMediaTaskRunner() {
  if (!media_thread_) {
    media_thread_.reset(new base::Thread("CastMediaThread"));
    base::Thread::Options options;
    // We need the media thread to be IO-capable to use the mixer service.
    options.message_pump_type = base::MessagePumpType::IO;
    options.priority = base::ThreadPriority::REALTIME_AUDIO;
    CHECK(media_thread_->StartWithOptions(options));
    // Start the media_resource_tracker as soon as the media thread is created.
    // There are services that run on the media thread that depend on it,
    // and we want to initialize it with the correct task runner before any
    // tasks that might use it are posted to the media thread.
    media_resource_tracker_ = new media::MediaResourceTracker(
        base::ThreadTaskRunnerHandle::Get(), media_thread_->task_runner());
  }
  return media_thread_->task_runner();
}

media::VideoResolutionPolicy*
CastContentBrowserClient::GetVideoResolutionPolicy() {
  return nullptr;
}

media::CmaBackendFactory* CastContentBrowserClient::GetCmaBackendFactory() {
  DCHECK(GetMediaTaskRunner()->BelongsToCurrentThread());
  if (!cma_backend_factory_) {
    cma_backend_factory_ = std::make_unique<media::CmaBackendFactoryImpl>(
        media_pipeline_backend_manager());
  }
  return cma_backend_factory_.get();
}

media::MediaResourceTracker*
CastContentBrowserClient::media_resource_tracker() {
  DCHECK(media_thread_);
  return media_resource_tracker_;
}

void CastContentBrowserClient::ResetMediaResourceTracker() {
  media_resource_tracker_->FinalizeAndDestroy();
  media_resource_tracker_ = nullptr;
}

media::MediaPipelineBackendManager*
CastContentBrowserClient::media_pipeline_backend_manager() {
  DCHECK(cast_browser_main_parts_);
  return cast_browser_main_parts_->media_pipeline_backend_manager();
}

std::unique_ptr<::media::AudioManager>
CastContentBrowserClient::CreateAudioManager(
    ::media::AudioLogFactory* audio_log_factory) {
  // Create the audio thread and initialize the CastSessionIdMap. We need to
  // initialize the CastSessionIdMap as soon as possible, so that the task
  // runner gets set before any calls to it.
  auto audio_thread = std::make_unique<::media::AudioThreadImpl>();
  shell::CastSessionIdMap::GetInstance(audio_thread->GetTaskRunner());

#if defined(USE_ALSA)
  return std::make_unique<media::CastAudioManagerAlsa>(
      std::move(audio_thread), audio_log_factory,
      base::BindRepeating(&CastContentBrowserClient::GetCmaBackendFactory,
                          base::Unretained(this)),
      base::BindRepeating(&shell::CastSessionIdMap::GetSessionId),
      base::CreateSingleThreadTaskRunner({content::BrowserThread::UI}),
      GetMediaTaskRunner(),
      ServiceConnector::MakeRemote(kBrowserProcessClientId),
      BUILDFLAG(ENABLE_CAST_AUDIO_MANAGER_MIXER));
#elif defined(OS_ANDROID)
  if (base::FeatureList::IsEnabled(kEnableChromeAudioManagerAndroid)) {
    LOG(INFO) << "Use AudioManagerAndroid instead of CastAudioManagerAndroid.";
    return std::make_unique<::media::AudioManagerAndroid>(
        std::move(audio_thread), audio_log_factory);
  }

  return std::make_unique<media::CastAudioManagerAndroid>(
      std::move(audio_thread), audio_log_factory,
      base::BindRepeating(&CastContentBrowserClient::GetCmaBackendFactory,
                          base::Unretained(this)),
      base::BindRepeating(&shell::CastSessionIdMap::GetSessionId),
      GetMediaTaskRunner(),
      ServiceConnector::MakeRemote(kBrowserProcessClientId));
#else
  return std::make_unique<media::CastAudioManager>(
      std::move(audio_thread), audio_log_factory,
      base::BindRepeating(&CastContentBrowserClient::GetCmaBackendFactory,
                          base::Unretained(this)),
      base::BindRepeating(&shell::CastSessionIdMap::GetSessionId),
      base::CreateSingleThreadTaskRunner({content::BrowserThread::UI}),
      GetMediaTaskRunner(),
      ServiceConnector::MakeRemote(kBrowserProcessClientId),
      BUILDFLAG(ENABLE_CAST_AUDIO_MANAGER_MIXER));
#endif
}

bool CastContentBrowserClient::OverridesAudioManager() {
  return true;
}

std::unique_ptr<::media::CdmFactory> CastContentBrowserClient::CreateCdmFactory(
    ::media::mojom::FrameInterfaceFactory* frame_interfaces) {
  url::Origin cdm_origin;
  if (!CastCdmOriginProvider::GetCdmOrigin(frame_interfaces, &cdm_origin))
    return nullptr;

  return std::make_unique<media::CastCdmFactory>(
      GetMediaTaskRunner(), cdm_origin, media_resource_tracker());
}

media::MediaCapsImpl* CastContentBrowserClient::media_caps() {
  DCHECK(cast_browser_main_parts_);
  return cast_browser_main_parts_->media_caps();
}

#if !defined(OS_ANDROID) && !defined(OS_FUCHSIA)
scoped_refptr<device::BluetoothAdapterCast>
CastContentBrowserClient::CreateBluetoothAdapter() {
  NOTREACHED() << "Bluetooth Adapter is not supported!";
  return nullptr;
}
#endif  // !defined(OS_ANDROID) && !defined(OS_FUCHSIA)

void CastContentBrowserClient::SetMetricsClientId(
    const std::string& client_id) {}

void CastContentBrowserClient::RegisterMetricsProviders(
    ::metrics::MetricsService* metrics_service) {}

bool CastContentBrowserClient::EnableRemoteDebuggingImmediately() {
  return true;
}

std::vector<std::string> CastContentBrowserClient::GetStartupServices() {
  return {
#if BUILDFLAG(ENABLE_EXTERNAL_MOJO_SERVICES)
    external_mojo::BrokerService::kServiceName
#endif
  };
}

std::unique_ptr<content::BrowserMainParts>
CastContentBrowserClient::CreateBrowserMainParts(
    const content::MainFunctionParams& parameters) {
  DCHECK(!cast_browser_main_parts_);

  auto main_parts = CastBrowserMainParts::Create(parameters, this);

  cast_browser_main_parts_ = main_parts.get();
  CastBrowserProcess::GetInstance()->SetCastContentBrowserClient(this);

  return main_parts;
}

void CastContentBrowserClient::RenderProcessWillLaunch(
    content::RenderProcessHost* host) {
#if defined(OS_ANDROID)
  // Cast on Android always allows persisting data.
  //
  // Cast on Android build always uses kForceVideoOverlays command line switch
  // such that secure codecs can always be rendered.
  //
  // TODO(yucliu): On Clank, secure codecs support is tied to AndroidOverlay.
  // Remove kForceVideoOverlays and swtich to the Clank model for secure codecs
  // support.
  host->AddFilter(new cdm::CdmMessageFilterAndroid(true, true));
#endif  // defined(OS_ANDROID)

#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  int render_process_id = host->GetID();
  content::BrowserContext* browser_context =
      cast_browser_main_parts_->browser_context();
  host->AddFilter(new extensions::ExtensionMessageFilter(render_process_id,
                                                         browser_context));
  host->AddFilter(new extensions::ExtensionsGuestViewMessageFilter(
      render_process_id, browser_context));
  host->AddFilter(
      new CastExtensionMessageFilter(render_process_id, browser_context));
#endif
}

bool CastContentBrowserClient::IsHandledURL(const GURL& url) {
  if (!url.is_valid())
    return false;

  static const char* const kProtocolList[] = {
      content::kChromeUIScheme, content::kChromeDevToolsScheme,
      kChromeResourceScheme,    url::kBlobScheme,
      url::kDataScheme,         url::kFileSystemScheme,
  };

  const std::string& scheme = url.scheme();
  for (size_t i = 0; i < base::size(kProtocolList); ++i) {
    if (scheme == kProtocolList[i])
      return true;
  }

  if (scheme == url::kFileScheme) {
    return base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kEnableLocalFileAccesses);
  }

  return false;
}

void CastContentBrowserClient::SiteInstanceGotProcess(
    content::SiteInstance* site_instance) {
#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  // If this isn't an extension renderer there's nothing to do.
  extensions::ExtensionRegistry* registry =
      extensions::ExtensionRegistry::Get(site_instance->GetBrowserContext());
  const extensions::Extension* extension =
      registry->enabled_extensions().GetExtensionOrAppByURL(
          site_instance->GetSiteURL());
  if (!extension)
    return;
  extensions::ProcessMap::Get(cast_browser_main_parts_->browser_context())
      ->Insert(extension->id(), site_instance->GetProcess()->GetID(),
               site_instance->GetId());
#endif
}

void CastContentBrowserClient::AppendExtraCommandLineSwitches(
    base::CommandLine* command_line,
    int child_process_id) {
  std::string process_type =
      command_line->GetSwitchValueNative(switches::kProcessType);
  base::CommandLine* browser_command_line =
      base::CommandLine::ForCurrentProcess();

#if !defined(OS_FUCHSIA)
#if defined(OS_ANDROID)
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kEnableCrashReporter)) {
    command_line->AppendSwitch(switches::kEnableCrashReporter);
  }
#else
  // IsCrashReporterEnabled() is set when InitCrashReporter() is called, and
  // controlled by GetBreakpadClient()->EnableBreakpadForProcess(), therefore
  // it's ok to add switch to every process here.
  if (breakpad::IsCrashReporterEnabled()) {
    command_line->AppendSwitch(switches::kEnableCrashReporter);
  }
#endif  // defined(OS_ANDROID)
#endif  // !defined(OS_FUCHSIA)

  // Command-line for different processes.
  if (process_type == switches::kRendererProcess) {
    // Any browser command-line switches that should be propagated to
    // the renderer go here.
    static const char* const kForwardSwitches[] = {
        switches::kCastAppBackgroundColor,
        switches::kForceMediaResolutionHeight,
        switches::kForceMediaResolutionWidth,
        network::switches::kUnsafelyTreatInsecureOriginAsSecure};
    command_line->CopySwitchesFrom(*browser_command_line, kForwardSwitches,
                                   base::size(kForwardSwitches));
  } else if (process_type == switches::kUtilityProcess) {
    if (browser_command_line->HasSwitch(switches::kAudioOutputChannels)) {
      command_line->AppendSwitchASCII(switches::kAudioOutputChannels,
                                      browser_command_line->GetSwitchValueASCII(
                                          switches::kAudioOutputChannels));
    }
  } else if (process_type == switches::kGpuProcess) {
#if defined(OS_LINUX) || defined(OS_CHROMEOS)
    // Necessary for accelerated 2d canvas.  By default on Linux, Chromium
    // assumes GLES2 contexts can be lost to a power-save mode, which breaks GPU
    // canvas apps.
    command_line->AppendSwitch(switches::kGpuNoContextLost);
#endif

#if defined(USE_AURA)
    static const char* const kForwardSwitches[] = {
        switches::kCastInitialScreenHeight,
        switches::kCastInitialScreenWidth,
        switches::kVSyncInterval,
    };
    command_line->CopySwitchesFrom(*browser_command_line, kForwardSwitches,
                                   base::size(kForwardSwitches));

    auto display = display::Screen::GetScreen()->GetPrimaryDisplay();
    gfx::Size res = display.GetSizeInPixel();
    if (display.rotation() == display::Display::ROTATE_90 ||
        display.rotation() == display::Display::ROTATE_270) {
      res = gfx::Size(res.height(), res.width());
    }

    if (!command_line->HasSwitch(switches::kCastInitialScreenWidth)) {
      command_line->AppendSwitchASCII(switches::kCastInitialScreenWidth,
                                      base::NumberToString(res.width()));
    }
    if (!command_line->HasSwitch(switches::kCastInitialScreenHeight)) {
      command_line->AppendSwitchASCII(switches::kCastInitialScreenHeight,
                                      base::NumberToString(res.height()));
    }

    if (chromecast::IsFeatureEnabled(kSingleBuffer)) {
      command_line->AppendSwitchASCII(switches::kGraphicsBufferCount, "1");
    } else if (chromecast::IsFeatureEnabled(chromecast::kTripleBuffer720)) {
      command_line->AppendSwitchASCII(switches::kGraphicsBufferCount, "3");
    }
#endif  // defined(USE_AURA)
  }
}

std::string CastContentBrowserClient::GetAcceptLangs(
    content::BrowserContext* context) {
  return CastHttpUserAgentSettings::AcceptLanguage();
}

network::mojom::NetworkContext*
CastContentBrowserClient::GetSystemNetworkContext() {
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  return cast_network_contexts_->GetSystemContext();
}

void CastContentBrowserClient::OverrideWebkitPrefs(
    content::RenderViewHost* render_view_host,
    blink::web_pref::WebPreferences* prefs) {
  prefs->allow_scripts_to_close_windows = true;
  // TODO(halliwell): http://crbug.com/391089. This pref defaults to to true
  // because some content providers such as YouTube use plain http requests
  // to retrieve media data chunks while running in a https page. This pref
  // should be disabled once all the content providers are no longer doing that.
  prefs->allow_running_insecure_content = true;

  // Enable 5% margins for WebVTT cues to keep within title-safe area
  prefs->text_track_margin_percentage = 5;

  prefs->hide_scrollbars = true;

  // Disable images rendering in Cast for Audio configuration
#if BUILDFLAG(IS_CAST_AUDIO_ONLY)
  prefs->images_enabled = false;
#endif

#if defined(OS_ANDROID)
  // Enable the television style for viewport so that all cast apps have a
  // 1280px wide layout viewport by default.
  DCHECK(prefs->viewport_enabled);
  DCHECK(prefs->viewport_meta_enabled);
  prefs->viewport_style = blink::web_pref::ViewportStyle::kTelevision;
#endif  // defined(OS_ANDROID)

  // Disable WebSQL databases by default.
  prefs->databases_enabled = false;
  content::WebContents* web_contents =
      content::WebContents::FromRenderViewHost(render_view_host);
  if (web_contents) {
    chromecast::CastWebContents* cast_web_contents =
        chromecast::CastWebContents::FromWebContents(web_contents);
    if (cast_web_contents && cast_web_contents->is_websql_enabled()) {
      prefs->databases_enabled = true;
    }
  }

  prefs->preferred_color_scheme =
      static_cast<blink::mojom::PreferredColorScheme>(
          CastBrowserProcess::GetInstance()->pref_service()->GetInteger(
              prefs::kWebColorScheme));

  // After all other default settings are set, check and see if there are any
  // specific overrides for the WebContents.
  CastWebPreferences* web_preferences =
      static_cast<CastWebPreferences*>(web_contents->GetUserData(
          CastWebPreferences::kCastWebPreferencesDataKey));
  if (web_preferences)
    web_preferences->Update(prefs);
}

std::string CastContentBrowserClient::GetApplicationLocale() {
  const std::string locale(base::i18n::GetConfiguredLocale());
  return locale.empty() ? "en-US" : locale;
}

scoped_refptr<content::QuotaPermissionContext>
CastContentBrowserClient::CreateQuotaPermissionContext() {
  return new CastQuotaPermissionContext();
}

void CastContentBrowserClient::AllowCertificateError(
    content::WebContents* web_contents,
    int cert_error,
    const net::SSLInfo& ssl_info,
    const GURL& request_url,
    bool is_main_frame_request,
    bool strict_enforcement,
    base::OnceCallback<void(content::CertificateRequestResultType)> callback) {
  // Allow developers to override certificate errors.
  // Otherwise, any fatal certificate errors will cause an abort.
  if (callback) {
    std::move(callback).Run(content::CERTIFICATE_REQUEST_RESULT_TYPE_CANCEL);
  }
  return;
}

base::OnceClosure CastContentBrowserClient::SelectClientCertificate(
    content::WebContents* web_contents,
    net::SSLCertRequestInfo* cert_request_info,
    net::ClientCertIdentityList client_certs,
    std::unique_ptr<content::ClientCertificateDelegate> delegate) {
  GURL requesting_url("https://" + cert_request_info->host_and_port.ToString());

  if (!requesting_url.is_valid()) {
    LOG(ERROR) << "Invalid URL string: "
               << requesting_url.possibly_invalid_spec();
    delegate->ContinueWithCertificate(nullptr, nullptr);
    return base::OnceClosure();
  }

  // In our case there are no relevant certs in |client_certs|. The cert
  // we need to return (if permitted) is the Cast device cert, which we can
  // access directly through the ClientAuthSigner instance. However, we need to
  // be on the IO thread to determine whether the app is whitelisted to return
  // it.
  // Subsequently, the callback must then itself be performed back here
  // on the UI thread.
  //
  // TODO(davidben): Stop using child ID to identify an app.
  std::string session_id =
      CastNavigationUIData::GetSessionIdForWebContents(web_contents);
  DCHECK_CURRENTLY_ON(content::BrowserThread::UI);
  base::PostTask(
      FROM_HERE, {content::BrowserThread::IO},
      base::BindOnce(
          &CastContentBrowserClient::SelectClientCertificateOnIOThread,
          base::Unretained(this), requesting_url, session_id,
          web_contents->GetMainFrame()->GetProcess()->GetID(),
          web_contents->GetMainFrame()->GetRoutingID(),
          base::SequencedTaskRunnerHandle::Get(),
          base::BindOnce(
              &content::ClientCertificateDelegate::ContinueWithCertificate,
              base::Owned(delegate.release()))));
  return base::OnceClosure();
}

bool CastContentBrowserClient::IsWhitelisted(
    const GURL& /* gurl */,
    const std::string& /* session_id */,
    int /* render_process_id */,
    int /* render_frame_id */,
    bool /* for_device_auth */) {
  return false;
}

void CastContentBrowserClient::SelectClientCertificateOnIOThread(
    GURL requesting_url,
    const std::string& session_id,
    int render_process_id,
    int render_frame_id,
    scoped_refptr<base::SequencedTaskRunner> original_runner,
    base::OnceCallback<void(scoped_refptr<net::X509Certificate>,
                            scoped_refptr<net::SSLPrivateKey>)>
        continue_callback) {
  DCHECK_CURRENTLY_ON(content::BrowserThread::IO);
  if (IsWhitelisted(requesting_url, session_id, render_process_id,
                    render_frame_id, false)) {
    original_runner->PostTask(
        FROM_HERE, base::BindOnce(std::move(continue_callback), DeviceCert(),
                                  DeviceKey()));
    return;
  } else {
    LOG(ERROR) << "Invalid host for client certificate request: "
               << requesting_url.host()
               << " with render_process_id: " << render_process_id
               << " and render_frame_id: " << render_frame_id;
  }
  original_runner->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(continue_callback), nullptr, nullptr));
}

bool CastContentBrowserClient::CanCreateWindow(
    content::RenderFrameHost* opener,
    const GURL& opener_url,
    const GURL& opener_top_level_frame_url,
    const url::Origin& source_origin,
    content::mojom::WindowContainerType container_type,
    const GURL& target_url,
    const content::Referrer& referrer,
    const std::string& frame_name,
    WindowOpenDisposition disposition,
    const blink::mojom::WindowFeatures& features,
    bool user_gesture,
    bool opener_suppressed,
    bool* no_javascript_access) {
  *no_javascript_access = true;
  return false;
}

void CastContentBrowserClient::GetApplicationMediaInfo(
    std::string* application_session_id,
    bool* mixer_audio_enabled,
    content::RenderFrameHost* render_frame_host) {
  content::WebContents* web_contents =
      content::WebContents::FromRenderFrameHost(render_frame_host);
  if (web_contents) {
    *application_session_id =
        CastNavigationUIData::GetSessionIdForWebContents(web_contents);
    chromecast::CastWebContents* cast_web_contents =
        chromecast::CastWebContents::FromWebContents(web_contents);
    *mixer_audio_enabled =
        (cast_web_contents && cast_web_contents->is_mixer_audio_enabled());
  }
}

base::Optional<service_manager::Manifest>
CastContentBrowserClient::GetServiceManifestOverlay(
    base::StringPiece service_name) {
  if (service_name == content::mojom::kBrowserServiceName)
    return GetCastContentBrowserOverlayManifest();

  return base::nullopt;
}

std::vector<service_manager::Manifest>
CastContentBrowserClient::GetExtraServiceManifests() {
  // NOTE: This could be simplified and the list of manifests could be inlined.
  // Not done yet since it would require touching downstream cast code.
  return GetCastContentPackagedServicesOverlayManifest().packaged_services;
}

void CastContentBrowserClient::GetAdditionalMappedFilesForChildProcess(
    const base::CommandLine& command_line,
    int child_process_id,
    content::PosixFileDescriptorInfo* mappings) {
#if defined(OS_ANDROID)
  mappings->ShareWithRegion(
      kAndroidPakDescriptor,
      base::GlobalDescriptors::GetInstance()->Get(kAndroidPakDescriptor),
      base::GlobalDescriptors::GetInstance()->GetRegion(kAndroidPakDescriptor));
#endif  // defined(OS_ANDROID)
#if !defined(OS_FUCHSIA)
  // TODO(crbug.com/753619): Enable crash reporting on Fuchsia.
  int crash_signal_fd = GetCrashSignalFD(command_line);
  if (crash_signal_fd >= 0) {
    mappings->Share(kCrashDumpSignal, crash_signal_fd);
  }
#endif  // !defined(OS_FUCHSIA)
}

void CastContentBrowserClient::GetAdditionalWebUISchemes(
    std::vector<std::string>* additional_schemes) {
  additional_schemes->push_back(kChromeResourceScheme);
}

content::DevToolsManagerDelegate*
CastContentBrowserClient::GetDevToolsManagerDelegate() {
  return new CastDevToolsManagerDelegate();
}

std::unique_ptr<content::NavigationUIData>
CastContentBrowserClient::GetNavigationUIData(
    content::NavigationHandle* navigation_handle) {
  DCHECK(navigation_handle);

  content::WebContents* web_contents = navigation_handle->GetWebContents();
  DCHECK(web_contents);

  std::string session_id =
      CastNavigationUIData::GetSessionIdForWebContents(web_contents);
  return std::make_unique<CastNavigationUIData>(session_id);
}

bool CastContentBrowserClient::ShouldEnableStrictSiteIsolation() {
  return false;
}

scoped_refptr<net::X509Certificate> CastContentBrowserClient::DeviceCert() {
  return nullptr;
}

scoped_refptr<net::SSLPrivateKey> CastContentBrowserClient::DeviceKey() {
  return nullptr;
}

#if defined(OS_ANDROID)
int CastContentBrowserClient::GetCrashSignalFD(
    const base::CommandLine& command_line) {
  return crashpad::CrashHandlerHost::Get()->GetDeathSignalSocket();
}
#elif !defined(OS_FUCHSIA)
int CastContentBrowserClient::GetCrashSignalFD(
    const base::CommandLine& command_line) {
  std::string process_type =
      command_line.GetSwitchValueASCII(switches::kProcessType);

  if (process_type == switches::kRendererProcess ||
      process_type == switches::kGpuProcess ||
      process_type == switches::kUtilityProcess) {
    breakpad::CrashHandlerHostLinux* crash_handler =
        crash_handlers_[process_type];
    if (!crash_handler) {
      crash_handler = CreateCrashHandlerHost(process_type);
      crash_handlers_[process_type] = crash_handler;
    }
    return crash_handler->GetDeathSignalSocket();
  }

  return -1;
}

breakpad::CrashHandlerHostLinux*
CastContentBrowserClient::CreateCrashHandlerHost(
    const std::string& process_type) {
  // Let cast shell dump to /tmp. Internal minidump generator code can move it
  // to /data/minidumps later, since /data/minidumps is file lock-controlled.
  base::FilePath dumps_path;
  base::PathService::Get(base::DIR_TEMP, &dumps_path);

  // Alway set "upload" to false to use our own uploader.
  breakpad::CrashHandlerHostLinux* crash_handler =
      new breakpad::CrashHandlerHostLinux(process_type, dumps_path,
                                          false /* upload */);
  // StartUploaderThread() even though upload is diferred.
  // Breakpad-related memory is freed in the uploader thread.
  crash_handler->StartUploaderThread();
  return crash_handler;
}
#endif  // defined(OS_ANDROID)

std::vector<std::unique_ptr<content::NavigationThrottle>>
CastContentBrowserClient::CreateThrottlesForNavigation(
    content::NavigationHandle* handle) {
  std::vector<std::unique_ptr<content::NavigationThrottle>> throttles;
#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  // If this isn't an extension renderer there's nothing to do.
  content::SiteInstance* site_instance = handle->GetStartingSiteInstance();
  if (site_instance) {
    extensions::ExtensionRegistry* registry =
        extensions::ExtensionRegistry::Get(site_instance->GetBrowserContext());
    const extensions::Extension* extension =
        registry->enabled_extensions().GetExtensionOrAppByURL(
            site_instance->GetSiteURL());
    if (extension) {
      throttles.push_back(std::make_unique<DefaultNavigationThrottle>(
          handle, content::NavigationThrottle::CANCEL_AND_IGNORE));
    }
  }
#endif

  if (chromecast::IsFeatureEnabled(kEnableGeneralAudienceBrowsing)) {
    throttles.push_back(
        std::make_unique<GeneralAudienceBrowsingNavigationThrottle>(
            handle, general_audience_browsing_service_.get()));
  }

#if (defined(OS_LINUX) || defined(OS_CHROMEOS)) && defined(USE_OZONE)
  auto webview_throttle = WebviewController::MaybeGetNavigationThrottle(handle);
  if (webview_throttle) {
    throttles.push_back(std::move(webview_throttle));
  }
#endif  // (defined(OS_LINUX) || defined(OS_CHROMEOS)) && defined(USE_OZONE)

  return throttles;
}

void CastContentBrowserClient::RegisterNonNetworkNavigationURLLoaderFactories(
    int frame_tree_node_id,
    base::UkmSourceId ukm_source_id,
    NonNetworkURLLoaderFactoryMap* factories) {
#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  content::WebContents* web_contents =
      content::WebContents::FromFrameTreeNodeId(frame_tree_node_id);
  auto* browser_context = web_contents->GetBrowserContext();
  auto extension_factory =
      extensions::CreateExtensionNavigationURLLoaderFactory(
          browser_context, ukm_source_id,
          !!extensions::WebViewGuest::FromWebContents(web_contents));
  factories->emplace(extensions::kExtensionScheme,
                     CastExtensionURLLoaderFactory::Create(
                         browser_context, std::move(extension_factory)));
#endif
}

void CastContentBrowserClient::RegisterNonNetworkSubresourceURLLoaderFactories(
    int render_process_id,
    int render_frame_id,
    NonNetworkURLLoaderFactoryMap* factories) {
  if (render_frame_id == MSG_ROUTING_NONE) {
    LOG(ERROR) << "Service worker not supported.";
    return;
  }
  content::RenderFrameHost* frame_host =
      content::RenderFrameHost::FromID(render_process_id, render_frame_id);

#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  auto* browser_context = frame_host->GetProcess()->GetBrowserContext();
  auto extension_factory = extensions::CreateExtensionURLLoaderFactory(
      render_process_id, render_frame_id);
  factories->emplace(extensions::kExtensionScheme,
                     CastExtensionURLLoaderFactory::Create(
                         browser_context, std::move(extension_factory)));
#endif

  factories->emplace(
      kChromeResourceScheme,
      content::CreateWebUIURLLoaderFactory(
          frame_host, kChromeResourceScheme,
          /*allowed_webui_hosts=*/base::flat_set<std::string>()));
}

void CastContentBrowserClient::OnNetworkServiceCreated(
    network::mojom::NetworkService* network_service) {
  // Need to set up global NetworkService state before anything else uses it.
  cast_network_contexts_->OnNetworkServiceCreated(network_service);
}

void CastContentBrowserClient::ConfigureNetworkContextParams(
    content::BrowserContext* context,
    bool in_memory,
    const base::FilePath& relative_partition_path,
    network::mojom::NetworkContextParams* network_context_params,
    network::mojom::CertVerifierCreationParams* cert_verifier_creation_params) {
  return cast_network_contexts_->ConfigureNetworkContextParams(
      context, in_memory, relative_partition_path, network_context_params,
      cert_verifier_creation_params);
}

bool CastContentBrowserClient::DoesSiteRequireDedicatedProcess(
    content::BrowserContext* browser_context,
    const GURL& effective_site_url) {
  // Always isolate extensions. This prevents site isolation from messing up
  // URLs.
#if BUILDFLAG(ENABLE_CHROMECAST_EXTENSIONS)
  return effective_site_url.SchemeIs(extensions::kExtensionScheme);
#else
  return false;
#endif
}

std::string CastContentBrowserClient::GetUserAgent() {
  return chromecast::shell::GetUserAgent();
}

void CastContentBrowserClient::CreateGeneralAudienceBrowsingService() {
  DCHECK(!general_audience_browsing_service_);
  general_audience_browsing_service_ =
      std::make_unique<GeneralAudienceBrowsingService>(
          cast_network_contexts_->GetSystemSharedURLLoaderFactory());
}

void CastContentBrowserClient::BindMediaRenderer(
    mojo::PendingReceiver<::media::mojom::Renderer> receiver) {
  auto media_task_runner = GetMediaTaskRunner();
  if (!media_task_runner->BelongsToCurrentThread()) {
    media_task_runner->PostTask(
        FROM_HERE, base::BindOnce(&CastContentBrowserClient::BindMediaRenderer,
                                  base::Unretained(this), std::move(receiver)));
    return;
  }

  ::media::MojoRendererService::Create(
      nullptr /* mojo_cdm_service_context */,
      std::make_unique<media::CastRenderer>(
          GetCmaBackendFactory(), std::move(media_task_runner),
          GetVideoModeSwitcher(), GetVideoResolutionPolicy(),
          base::UnguessableToken::Create(), nullptr /* frame_interfaces */),
      std::move(receiver));
}

}  // namespace shell
}  // namespace chromecast
