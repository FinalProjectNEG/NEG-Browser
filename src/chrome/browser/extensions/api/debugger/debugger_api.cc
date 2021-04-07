// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements the Chrome Extensions Debugger API.

#include "chrome/browser/extensions/api/debugger/debugger_api.h"

#include <stddef.h>

#include <map>
#include <memory>
#include <set>
#include <utility>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/scoped_observer.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/post_task.h"
#include "base/values.h"
#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/devtools/chrome_devtools_manager_delegate.h"
#include "chrome/browser/extensions/api/debugger/debugger_api_constants.h"
#include "chrome/browser/extensions/api/debugger/extension_dev_tools_infobar_delegate.h"
#include "chrome/browser/extensions/extension_service.h"
#include "chrome/browser/extensions/extension_tab_util.h"
#include "chrome/browser/extensions/extension_util.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/webui/chrome_web_ui_controller_factory.h"
#include "chrome/common/chrome_switches.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/devtools_agent_host.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/notification_source.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/render_widget_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/content_client.h"
#include "content/public/common/url_constants.h"
#include "content/public/common/url_utils.h"
#include "extensions/browser/event_router.h"
#include "extensions/browser/extension_host.h"
#include "extensions/browser/extension_registry.h"
#include "extensions/browser/extension_registry_observer.h"
#include "extensions/common/constants.h"
#include "extensions/common/error_utils.h"
#include "extensions/common/extension.h"
#include "extensions/common/manifest_constants.h"
#include "extensions/common/permissions/permissions_data.h"
#include "extensions/common/switches.h"

using content::DevToolsAgentHost;
using content::RenderProcessHost;
using content::RenderWidgetHost;
using content::WebContents;

namespace Attach = extensions::api::debugger::Attach;
namespace Detach = extensions::api::debugger::Detach;
namespace OnDetach = extensions::api::debugger::OnDetach;
namespace OnEvent = extensions::api::debugger::OnEvent;
namespace SendCommand = extensions::api::debugger::SendCommand;

namespace extensions {
class ExtensionRegistry;
class ExtensionDevToolsClientHost;

namespace {

// Helpers --------------------------------------------------------------------

void CopyDebuggee(Debuggee* dst, const Debuggee& src) {
  if (src.tab_id)
    dst->tab_id.reset(new int(*src.tab_id));
  if (src.extension_id)
    dst->extension_id.reset(new std::string(*src.extension_id));
  if (src.target_id)
    dst->target_id.reset(new std::string(*src.target_id));
}

// Returns true if the given |Extension| is allowed to attach to the specified
// |url|.
bool ExtensionMayAttachToURL(const Extension& extension,
                             const GURL& url,
                             Profile* profile,
                             std::string* error) {
  if (url == content::kUnreachableWebDataURL)
    return true;

  // NOTE: The `debugger` permission implies all URLs access (and indicates
  // such to the user), so we don't check explicit page access. However, we
  // still need to check if it's an otherwise-restricted URL.
  if (extension.permissions_data()->IsRestrictedUrl(url, error))
    return false;

  if (url.SchemeIsFile() && !util::AllowFileAccess(extension.id(), profile)) {
    *error = debugger_api_constants::kRestrictedError;
    return false;
  }

  return true;
}

constexpr char kBrowserTargetId[] = "browser";

constexpr char kPerfettoUIExtensionId[] = "lfmkphfpdbjijhpomgecfikhfohaoine";

bool ExtensionMayAttachToBrowser(const Extension& extension) {
  return extension.id() == kPerfettoUIExtensionId;
}

bool ExtensionMayAttachToWebContents(const Extension& extension,
                                     WebContents& web_contents,
                                     Profile* profile,
                                     std::string* error) {
  // This is *not* redundant to the checks below, as
  // web_contents.GetLastCommittedURL() may be different from
  // web_contents.GetMainFrame()->GetLastCommittedURL(), with the
  // former being a 'virtual' URL as obtained from NavigationEntry.
  if (!ExtensionMayAttachToURL(extension, web_contents.GetLastCommittedURL(),
                               profile, error)) {
    return false;
  }

  for (content::RenderFrameHost* rfh : web_contents.GetAllFrames()) {
    if (!ExtensionMayAttachToURL(extension, rfh->GetLastCommittedURL(), profile,
                                 error))
      return false;
  }
  return true;
}

bool ExtensionMayAttachToAgentHost(const Extension& extension,
                                   DevToolsAgentHost& agent_host,
                                   Profile* profile,
                                   std::string* error) {
  if (WebContents* wc = agent_host.GetWebContents())
    return ExtensionMayAttachToWebContents(extension, *wc, profile, error);

  return ExtensionMayAttachToURL(extension, agent_host.GetURL(), profile,
                                 error);
}

}  // namespace

// ExtensionDevToolsClientHost ------------------------------------------------

using AttachedClientHosts = std::set<ExtensionDevToolsClientHost*>;
base::LazyInstance<AttachedClientHosts>::Leaky g_attached_client_hosts =
    LAZY_INSTANCE_INITIALIZER;

class ExtensionDevToolsClientHost : public content::DevToolsAgentHostClient,
                                    public content::NotificationObserver,
                                    public ExtensionRegistryObserver {
 public:
  ExtensionDevToolsClientHost(Profile* profile,
                              DevToolsAgentHost* agent_host,
                              scoped_refptr<const Extension> extension,
                              const Debuggee& debuggee);

  ~ExtensionDevToolsClientHost() override;

  bool Attach();
  const std::string& extension_id() { return extension_->id(); }
  DevToolsAgentHost* agent_host() { return agent_host_.get(); }
  void RespondDetachedToPendingRequests();
  void Close();
  void SendMessageToBackend(DebuggerSendCommandFunction* function,
                            const std::string& method,
                            SendCommand::Params::CommandParams* command_params);

  // Closes connection as terminated by the user.
  void InfoBarDestroyed();

  // DevToolsAgentHostClient interface.
  void AgentHostClosed(DevToolsAgentHost* agent_host) override;
  void DispatchProtocolMessage(DevToolsAgentHost* agent_host,
                               base::span<const uint8_t> message) override;
  bool MayAttachToURL(const GURL& url, bool is_webui) override;
  bool MayAttachToBrowser() override;
  bool MayReadLocalFiles() override;
  bool MayWriteLocalFiles() override;

 private:
  using PendingRequests =
      std::map<int, scoped_refptr<DebuggerSendCommandFunction>>;

  void SendDetachedEvent();

  // content::NotificationObserver implementation.
  void Observe(int type,
               const content::NotificationSource& source,
               const content::NotificationDetails& details) override;

  // ExtensionRegistryObserver implementation.
  void OnExtensionUnloaded(content::BrowserContext* browser_context,
                           const Extension* extension,
                           UnloadedExtensionReason reason) override;

  Profile* profile_;
  scoped_refptr<DevToolsAgentHost> agent_host_;
  scoped_refptr<const Extension> extension_;
  Debuggee debuggee_;
  content::NotificationRegistrar registrar_;
  int last_request_id_ = 0;
  PendingRequests pending_requests_;
  std::unique_ptr<ExtensionDevToolsInfoBarDelegate::CallbackList::Subscription>
      subscription_;
  api::debugger::DetachReason detach_reason_ =
      api::debugger::DETACH_REASON_TARGET_CLOSED;

  // Listen to extension unloaded notification.
  ScopedObserver<ExtensionRegistry, ExtensionRegistryObserver>
      extension_registry_observer_{this};

  DISALLOW_COPY_AND_ASSIGN(ExtensionDevToolsClientHost);
};

ExtensionDevToolsClientHost::ExtensionDevToolsClientHost(
    Profile* profile,
    DevToolsAgentHost* agent_host,
    scoped_refptr<const Extension> extension,
    const Debuggee& debuggee)
    : profile_(profile),
      agent_host_(agent_host),
      extension_(std::move(extension)) {
  CopyDebuggee(&debuggee_, debuggee);

  g_attached_client_hosts.Get().insert(this);

  // ExtensionRegistryObserver listen extension unloaded and detach debugger
  // from there.
  extension_registry_observer_.Add(ExtensionRegistry::Get(profile_));

  // RVH-based agents disconnect from their clients when the app is terminating
  // but shared worker-based agents do not.
  // Disconnect explicitly to make sure that |this| observer is not leaked.
  registrar_.Add(this, chrome::NOTIFICATION_APP_TERMINATING,
                 content::NotificationService::AllSources());
}

bool ExtensionDevToolsClientHost::Attach() {
  // Attach to debugger and tell it we are ready.
  if (!agent_host_->AttachClient(this))
    return false;

  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          ::switches::kSilentDebuggerExtensionAPI)) {
    return true;
  }

  // We allow policy-installed extensions to circumvent the normal
  // infobar warning. See crbug.com/693621.
  if (Manifest::IsPolicyLocation(extension_->location()))
    return true;

  subscription_ = ExtensionDevToolsInfoBarDelegate::Create(
      extension_id(), extension_->name(),
      base::BindOnce(&ExtensionDevToolsClientHost::InfoBarDestroyed,
                     base::Unretained(this)));
  return true;
}

ExtensionDevToolsClientHost::~ExtensionDevToolsClientHost() {
  ExtensionDevToolsInfoBarDelegate::NotifyExtensionDetached(extension_id());
  g_attached_client_hosts.Get().erase(this);
}

// DevToolsAgentHostClient implementation.
void ExtensionDevToolsClientHost::AgentHostClosed(
    DevToolsAgentHost* agent_host) {
  DCHECK(agent_host == agent_host_.get());
  RespondDetachedToPendingRequests();
  SendDetachedEvent();
  delete this;
}

void ExtensionDevToolsClientHost::Close() {
  agent_host_->DetachClient(this);
  delete this;
}

void ExtensionDevToolsClientHost::SendMessageToBackend(
    DebuggerSendCommandFunction* function,
    const std::string& method,
    SendCommand::Params::CommandParams* command_params) {
  base::DictionaryValue protocol_request;
  int request_id = ++last_request_id_;
  pending_requests_[request_id] = function;
  protocol_request.SetInteger("id", request_id);
  protocol_request.SetString("method", method);
  if (command_params) {
    protocol_request.Set(
        "params", command_params->additional_properties.CreateDeepCopy());
  }

  std::string json;
  base::JSONWriter::Write(protocol_request, &json);

  agent_host_->DispatchProtocolMessage(this,
                                       base::as_bytes(base::make_span(json)));
}

void ExtensionDevToolsClientHost::InfoBarDestroyed() {
  detach_reason_ = api::debugger::DETACH_REASON_CANCELED_BY_USER;
  RespondDetachedToPendingRequests();
  SendDetachedEvent();
  Close();
}

void ExtensionDevToolsClientHost::RespondDetachedToPendingRequests() {
  for (const auto& it : pending_requests_)
    it.second->SendDetachedError();
  pending_requests_.clear();
}

void ExtensionDevToolsClientHost::SendDetachedEvent() {
  if (!EventRouter::Get(profile_))
    return;

  std::unique_ptr<base::ListValue> args(
      OnDetach::Create(debuggee_, detach_reason_));
  auto event =
      std::make_unique<Event>(events::DEBUGGER_ON_DETACH, OnDetach::kEventName,
                              std::move(args), profile_);
  EventRouter::Get(profile_)->DispatchEventToExtension(extension_id(),
                                                       std::move(event));
}

void ExtensionDevToolsClientHost::OnExtensionUnloaded(
    content::BrowserContext* browser_context,
    const Extension* extension,
    UnloadedExtensionReason reason) {
  if (extension->id() == extension_id())
    Close();
}

void ExtensionDevToolsClientHost::Observe(
    int type,
    const content::NotificationSource& source,
    const content::NotificationDetails& details) {
  DCHECK_EQ(chrome::NOTIFICATION_APP_TERMINATING, type);
  Close();
}

void ExtensionDevToolsClientHost::DispatchProtocolMessage(
    DevToolsAgentHost* agent_host,
    base::span<const uint8_t> message) {
  DCHECK(agent_host == agent_host_.get());
  if (!EventRouter::Get(profile_))
    return;

  base::StringPiece message_str(reinterpret_cast<const char*>(message.data()),
                                message.size());
  std::unique_ptr<base::Value> result = base::JSONReader::ReadDeprecated(
      message_str, base::JSON_REPLACE_INVALID_CHARACTERS);
  if (!result || !result->is_dict()) {
    LOG(ERROR) << "Tried to send invalid message to extension: " << message_str;
    return;
  }
  base::DictionaryValue* dictionary =
      static_cast<base::DictionaryValue*>(result.get());

  int id;
  if (!dictionary->GetInteger("id", &id)) {
    std::string method_name;
    if (!dictionary->GetString("method", &method_name))
      return;

    OnEvent::Params params;
    base::DictionaryValue* params_value;
    if (dictionary->GetDictionary("params", &params_value))
      params.additional_properties.Swap(params_value);

    std::unique_ptr<base::ListValue> args(
        OnEvent::Create(debuggee_, method_name, params));
    auto event =
        std::make_unique<Event>(events::DEBUGGER_ON_EVENT, OnEvent::kEventName,
                                std::move(args), profile_);
    EventRouter::Get(profile_)->DispatchEventToExtension(extension_id(),
                                                         std::move(event));
  } else {
    auto it = pending_requests_.find(id);
    if (it == pending_requests_.end())
      return;

    it->second->SendResponseBody(dictionary);
    pending_requests_.erase(it);
  }
}

bool ExtensionDevToolsClientHost::MayAttachToURL(const GURL& url,
                                                 bool is_webui) {
  if (is_webui)
    return false;
  // Allow the extension to attach to about:blank.
  if (url.is_empty() || url == "about:")
    return true;
  std::string error;
  return ExtensionMayAttachToURL(*extension_, url, profile_, &error);
}

bool ExtensionDevToolsClientHost::MayAttachToBrowser() {
  return ExtensionMayAttachToBrowser(*extension_);
}

bool ExtensionDevToolsClientHost::MayReadLocalFiles() {
  return util::AllowFileAccess(extension_->id(), profile_);
}

bool ExtensionDevToolsClientHost::MayWriteLocalFiles() {
  return false;
}

// DebuggerFunction -----------------------------------------------------------

DebuggerFunction::DebuggerFunction() : client_host_(nullptr) {}

DebuggerFunction::~DebuggerFunction() = default;

std::string DebuggerFunction::FormatErrorMessage(const std::string& format) {
  if (debuggee_.tab_id) {
    return ErrorUtils::FormatErrorMessage(
        format, debugger_api_constants::kTabTargetType,
        base::NumberToString(*debuggee_.tab_id));
  }
  if (debuggee_.extension_id) {
    return ErrorUtils::FormatErrorMessage(
        format, debugger_api_constants::kBackgroundPageTargetType,
        *debuggee_.extension_id);
  }

  return ErrorUtils::FormatErrorMessage(
      format, debugger_api_constants::kOpaqueTargetType, *debuggee_.target_id);
}

bool DebuggerFunction::InitAgentHost(std::string* error) {
  if (debuggee_.tab_id) {
    WebContents* web_contents = nullptr;
    bool result = ExtensionTabUtil::GetTabById(
        *debuggee_.tab_id, browser_context(), include_incognito_information(),
        &web_contents);
    if (result && web_contents) {
      if (!ExtensionMayAttachToWebContents(
              *extension(), *web_contents,
              Profile::FromBrowserContext(browser_context()), error)) {
        return false;
      }

      agent_host_ = DevToolsAgentHost::GetOrCreateFor(web_contents);
    }
  } else if (debuggee_.extension_id) {
    ExtensionHost* extension_host =
        ProcessManager::Get(browser_context())
            ->GetBackgroundHostForExtension(*debuggee_.extension_id);
    if (extension_host) {
      if (extension()->permissions_data()->IsRestrictedUrl(
              extension_host->GetLastCommittedURL(), error)) {
        return false;
      }
      agent_host_ =
          DevToolsAgentHost::GetOrCreateFor(extension_host->host_contents());
    }
  } else if (debuggee_.target_id) {
    scoped_refptr<DevToolsAgentHost> agent_host =
        DevToolsAgentHost::GetForId(*debuggee_.target_id);
    if (agent_host) {
      if (!ExtensionMayAttachToAgentHost(
              *extension(), *agent_host,
              Profile::FromBrowserContext(browser_context()), error)) {
        return false;
      }
      agent_host_ = std::move(agent_host);
    } else if (*debuggee_.target_id == kBrowserTargetId &&
               ExtensionMayAttachToBrowser(*extension())) {
      // TODO(caseq): get rid of the below code, browser agent host should
      // really be a singleton.
      // Re-use existing browser agent hosts.
      const std::string& extension_id = extension()->id();
      AttachedClientHosts& hosts = g_attached_client_hosts.Get();
      auto it = std::find_if(
          hosts.begin(), hosts.end(),
          [&extension_id](ExtensionDevToolsClientHost* client_host) {
            return client_host->extension_id() == extension_id &&
                   client_host->agent_host() &&
                   client_host->agent_host()->GetType() ==
                       DevToolsAgentHost::kTypeBrowser;
          });
      agent_host_ = it != hosts.end()
                        ? (*it)->agent_host()
                        : DevToolsAgentHost::CreateForBrowser(
                              nullptr /* tethering_task_runner */,
                              DevToolsAgentHost::CreateServerSocketCallback());
    }
  } else {
    *error = debugger_api_constants::kInvalidTargetError;
    return false;
  }

  if (!agent_host_.get()) {
    *error = FormatErrorMessage(debugger_api_constants::kNoTargetError);
    return false;
  }
  return true;
}

bool DebuggerFunction::InitClientHost(std::string* error) {
  if (!InitAgentHost(error))
    return false;

  client_host_ = FindClientHost();
  if (!client_host_) {
    *error = FormatErrorMessage(debugger_api_constants::kNotAttachedError);
    return false;
  }

  return true;
}

ExtensionDevToolsClientHost* DebuggerFunction::FindClientHost() {
  if (!agent_host_.get())
    return nullptr;

  const std::string& extension_id = extension()->id();
  DevToolsAgentHost* agent_host = agent_host_.get();
  AttachedClientHosts& hosts = g_attached_client_hosts.Get();
  auto it = std::find_if(
      hosts.begin(), hosts.end(),
      [&agent_host, &extension_id](ExtensionDevToolsClientHost* client_host) {
        return client_host->agent_host() == agent_host &&
               client_host->extension_id() == extension_id;
      });

  return it == hosts.end() ? nullptr : *it;
}

// DebuggerAttachFunction -----------------------------------------------------

DebuggerAttachFunction::DebuggerAttachFunction() = default;

DebuggerAttachFunction::~DebuggerAttachFunction() = default;

ExtensionFunction::ResponseAction DebuggerAttachFunction::Run() {
  std::unique_ptr<Attach::Params> params(Attach::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params.get());

  CopyDebuggee(&debuggee_, params->target);
  std::string error;
  if (!InitAgentHost(&error))
    return RespondNow(Error(std::move(error)));

  if (!DevToolsAgentHost::IsSupportedProtocolVersion(
          params->required_version)) {
    return RespondNow(Error(ErrorUtils::FormatErrorMessage(
        debugger_api_constants::kProtocolVersionNotSupportedError,
        params->required_version)));
  }

  if (FindClientHost()) {
    return RespondNow(Error(
        FormatErrorMessage(debugger_api_constants::kAlreadyAttachedError)));
  }

  auto host = std::make_unique<ExtensionDevToolsClientHost>(
      Profile::FromBrowserContext(browser_context()), agent_host_.get(),
      extension(), debuggee_);

  if (!host->Attach()) {
    return RespondNow(Error(debugger_api_constants::kRestrictedError));
  }

  host.release();  // An attached client host manages its own lifetime.
  return RespondNow(NoArguments());
}

// DebuggerDetachFunction -----------------------------------------------------

DebuggerDetachFunction::DebuggerDetachFunction() = default;

DebuggerDetachFunction::~DebuggerDetachFunction() = default;

ExtensionFunction::ResponseAction DebuggerDetachFunction::Run() {
  std::unique_ptr<Detach::Params> params(Detach::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params.get());

  CopyDebuggee(&debuggee_, params->target);
  std::string error;
  if (!InitClientHost(&error))
    return RespondNow(Error(std::move(error)));

  client_host_->RespondDetachedToPendingRequests();
  client_host_->Close();
  return RespondNow(NoArguments());
}

// DebuggerSendCommandFunction ------------------------------------------------

DebuggerSendCommandFunction::DebuggerSendCommandFunction() = default;

DebuggerSendCommandFunction::~DebuggerSendCommandFunction() = default;

ExtensionFunction::ResponseAction DebuggerSendCommandFunction::Run() {
  std::unique_ptr<SendCommand::Params> params(
      SendCommand::Params::Create(*args_));
  EXTENSION_FUNCTION_VALIDATE(params.get());

  CopyDebuggee(&debuggee_, params->target);
  std::string error;
  if (!InitClientHost(&error))
    return RespondNow(Error(std::move(error)));

  client_host_->SendMessageToBackend(this, params->method,
      params->command_params.get());
  if (did_respond())
    return AlreadyResponded();
  return RespondLater();
}

void DebuggerSendCommandFunction::SendResponseBody(
    base::DictionaryValue* response) {
  base::Value* error_body;
  if (response->Get("error", &error_body)) {
    std::string error;
    base::JSONWriter::Write(*error_body, &error);
    Respond(Error(std::move(error)));
    return;
  }

  base::DictionaryValue* result_body;
  SendCommand::Results::Result result;
  if (response->GetDictionary("result", &result_body))
    result.additional_properties.Swap(result_body);

  Respond(ArgumentList(SendCommand::Results::Create(result)));
}

void DebuggerSendCommandFunction::SendDetachedError() {
  Respond(Error(debugger_api_constants::kDetachedWhileHandlingError));
}

// DebuggerGetTargetsFunction -------------------------------------------------

namespace {

const char kTargetIdField[] = "id";
const char kTargetTypeField[] = "type";
const char kTargetTitleField[] = "title";
const char kTargetAttachedField[] = "attached";
const char kTargetUrlField[] = "url";
const char kTargetFaviconUrlField[] = "faviconUrl";
const char kTargetTabIdField[] = "tabId";
const char kTargetExtensionIdField[] = "extensionId";
const char kTargetTypePage[] = "page";
const char kTargetTypeBackgroundPage[] = "background_page";
const char kTargetTypeWorker[] = "worker";
const char kTargetTypeOther[] = "other";

std::unique_ptr<base::DictionaryValue> SerializeTarget(
    scoped_refptr<DevToolsAgentHost> host) {
  std::unique_ptr<base::DictionaryValue> dictionary(
      new base::DictionaryValue());
  dictionary->SetString(kTargetIdField, host->GetId());
  dictionary->SetString(kTargetTitleField, host->GetTitle());
  dictionary->SetBoolean(kTargetAttachedField, host->IsAttached());
  dictionary->SetString(kTargetUrlField, host->GetURL().spec());

  std::string type = host->GetType();
  std::string target_type = kTargetTypeOther;
  if (type == DevToolsAgentHost::kTypePage) {
    int tab_id =
        extensions::ExtensionTabUtil::GetTabId(host->GetWebContents());
    dictionary->SetInteger(kTargetTabIdField, tab_id);
    target_type = kTargetTypePage;
  } else if (type == ChromeDevToolsManagerDelegate::kTypeBackgroundPage) {
    dictionary->SetString(kTargetExtensionIdField, host->GetURL().host());
    target_type = kTargetTypeBackgroundPage;
  } else if (type == DevToolsAgentHost::kTypeServiceWorker ||
             type == DevToolsAgentHost::kTypeSharedWorker) {
    target_type = kTargetTypeWorker;
  }

  dictionary->SetString(kTargetTypeField, target_type);

  GURL favicon_url = host->GetFaviconURL();
  if (favicon_url.is_valid())
    dictionary->SetString(kTargetFaviconUrlField, favicon_url.spec());

  return dictionary;
}

}  // namespace

DebuggerGetTargetsFunction::DebuggerGetTargetsFunction() = default;

DebuggerGetTargetsFunction::~DebuggerGetTargetsFunction() = default;

ExtensionFunction::ResponseAction DebuggerGetTargetsFunction::Run() {
  content::DevToolsAgentHost::List list = DevToolsAgentHost::GetOrCreateAll();
  std::unique_ptr<base::ListValue> result(new base::ListValue());
  for (size_t i = 0; i < list.size(); ++i)
    result->Append(SerializeTarget(list[i]));

  return RespondNow(OneArgument(std::move(result)));
}

}  // namespace extensions
