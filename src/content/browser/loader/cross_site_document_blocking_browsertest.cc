// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ostream>
#include <string>
#include <utility>

#include "base/base64.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/macros.h"
#include "base/strings/pattern.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "content/browser/site_instance_impl.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/navigation_entry.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/content_features.h"
#include "content/public/common/content_switches.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_navigation_observer.h"
#include "content/public/test/test_utils.h"
#include "content/public/test/url_loader_interceptor.h"
#include "content/shell/browser/shell.h"
#include "content/test/test_content_browser_client.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/test_support/test_utils.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/test/embedded_test_server/controllable_http_response.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "services/network/public/cpp/cross_origin_read_blocking.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/initiator_lock_compatibility.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/test/test_url_loader_client.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "third_party/blink/public/mojom/loader/resource_load_info.mojom-shared.h"

namespace content {

using testing::Not;
using testing::HasSubstr;
using Action = network::CrossOriginReadBlocking::Action;
using CorbMimeType = network::CrossOriginReadBlocking::MimeType;
using RequestInitiatorOriginLockCompatibility =
    network::InitiatorLockCompatibility;

namespace {

enum CorbExpectations {
  kShouldBeBlocked = 1 << 0,
  kShouldBeSniffed = 1 << 1,

  kShouldBeAllowedWithoutSniffing = 0,
  kShouldBeBlockedWithoutSniffing = kShouldBeBlocked,
  kShouldBeSniffedAndAllowed = kShouldBeSniffed,
  kShouldBeSniffedAndBlocked = kShouldBeSniffed | kShouldBeBlocked,
};

std::ostream& operator<<(std::ostream& os, const CorbExpectations& value) {
  if (value == 0) {
    os << "(none)";
    return os;
  }

  os << "( ";
  if (0 != (value & kShouldBeBlocked))
    os << "kShouldBeBlocked ";
  if (0 != (value & kShouldBeSniffed))
    os << "kShouldBeSniffed ";
  os << ")";
  return os;
}

// Ensure the correct histograms are incremented for blocking events.
// Assumes the resource type is XHR.
void InspectHistograms(
    const base::HistogramTester& histograms,
    const CorbExpectations& expectations,
    const std::string& resource_name,
    blink::mojom::ResourceType resource_type,
    bool special_request_initiator_origin_lock_check_for_appcache = false) {
  FetchHistogramsFromChildProcesses();

  auto expected_lock_compatibility =
      special_request_initiator_origin_lock_check_for_appcache
          ? network::InitiatorLockCompatibility::kBrowserProcess
          : network::InitiatorLockCompatibility::kCompatibleLock;
  histograms.ExpectUniqueSample(
      "NetworkService.URLLoader.RequestInitiatorOriginLockCompatibility",
      expected_lock_compatibility, 1);

  CorbMimeType expected_mime_type = CorbMimeType::kInvalidMimeType;
  if (base::MatchPattern(resource_name, "*.html")) {
    expected_mime_type = CorbMimeType::kHtml;
  } else if (base::MatchPattern(resource_name, "*.xml")) {
    expected_mime_type = CorbMimeType::kXml;
  } else if (base::MatchPattern(resource_name, "*.json")) {
    expected_mime_type = CorbMimeType::kJson;
  } else if (base::MatchPattern(resource_name, "*.txt")) {
    expected_mime_type = CorbMimeType::kPlain;
  } else if (base::MatchPattern(resource_name, "*.zip") ||
             base::MatchPattern(resource_name, "*.pdf")) {
    expected_mime_type = CorbMimeType::kNeverSniffed;
  } else {
    expected_mime_type = CorbMimeType::kOthers;
  }

  // Determine the appropriate histograms, including a start and end action
  // (which are verified in unit tests), a read size if it was sniffed, and
  // additional blocked metrics if it was blocked.
  base::HistogramTester::CountsMap expected_counts;
  std::string base = "SiteIsolation.XSD.Browser";
  expected_counts[base + ".Action"] = 2;
  if (0 != (expectations & kShouldBeBlocked)) {
    expected_counts[base + ".Blocked.CanonicalMimeType"] = 1;
  }

  // Make sure that the expected metrics, and only those metrics, were
  // incremented.
  EXPECT_THAT(histograms.GetTotalCountsForPrefix("SiteIsolation.XSD.Browser"),
              testing::ContainerEq(expected_counts))
      << "For resource_name=" << resource_name
      << ", expectations=" << expectations;

  // Determine if the bucket for the resource type (XHR) was incremented.
  if (0 != (expectations & kShouldBeBlocked)) {
    EXPECT_THAT(histograms.GetAllSamples(base + ".Blocked.CanonicalMimeType"),
                testing::ElementsAre(
                    base::Bucket(static_cast<int>(expected_mime_type), 1)))
        << "The wrong CorbMimeType bucket was incremented.";
  }

  // SiteIsolation.XSD.Browser.Action should always include kResponseStarted.
  histograms.ExpectBucketCount(base + ".Action",
                               static_cast<int>(Action::kResponseStarted), 1);

  // Second value in SiteIsolation.XSD.Browser.Action depends on |expectations|.
  Action expected_action = static_cast<Action>(-1);
  if (expectations & kShouldBeBlocked) {
    if (expectations & kShouldBeSniffed)
      expected_action = Action::kBlockedAfterSniffing;
    else
      expected_action = Action::kBlockedWithoutSniffing;
  } else {
    if (expectations & kShouldBeSniffed)
      expected_action = Action::kAllowedAfterSniffing;
    else
      expected_action = Action::kAllowedWithoutSniffing;
  }
  histograms.ExpectBucketCount(base + ".Action",
                               static_cast<int>(expected_action), 1);
}

// Gets contents of a file at //content/test/data/<dir>/<file>.
std::string GetTestFileContents(const char* dir, const char* file) {
  base::ScopedAllowBlockingForTesting allow_io;
  base::FilePath path = GetTestFilePath(dir, file);
  std::string result;
  EXPECT_TRUE(ReadFileToString(path, &result));
  return result;
}

// Helper for intercepting a resource request to the given URL and capturing the
// response headers and body.
//
// Note that after the request completes, the original requestor (e.g. the
// renderer) will see an injected request failure (this is easier to accomplish
// than forwarding the intercepted response to the original requestor),
class RequestInterceptor {
 public:
  // Start intercepting requests to |url_to_intercept|.
  explicit RequestInterceptor(const GURL& url_to_intercept)
      : url_to_intercept_(url_to_intercept),
        interceptor_(
            base::BindRepeating(&RequestInterceptor::InterceptorCallback,
                                base::Unretained(this))) {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(url_to_intercept.is_valid());

    pending_test_client_remote_ = test_client_.CreateRemote();
  }

  ~RequestInterceptor() {
    WaitForCleanUpOnInterceptorThread(
        network::mojom::URLResponseHead::New(), "",
        network::URLLoaderCompletionStatus(net::ERR_NOT_IMPLEMENTED));
  }

  // Waits until a request gets intercepted and completed.
  void WaitForRequestCompletion() {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(!request_completed_);
    test_client_.RunUntilComplete();

    // Read the intercepted response body into |body_|.
    if (test_client_.completion_status().error_code == net::OK) {
      base::RunLoop run_loop;
      ReadBody(run_loop.QuitClosure());
      run_loop.Run();
    }

    // Wait until IO cleanup completes.
    WaitForCleanUpOnInterceptorThread(test_client_.response_head().Clone(),
                                      body_, test_client_.completion_status());

    // Mark the request as completed (for DCHECK purposes).
    request_completed_ = true;
  }

  const network::URLLoaderCompletionStatus& completion_status() const {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(request_completed_);
    return test_client_.completion_status();
  }

  const network::mojom::URLResponseHeadPtr& response_head() const {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(request_completed_);
    return test_client_.response_head();
  }

  const std::string& response_body() const {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);
    DCHECK(request_completed_);
    return body_;
  }

  void Verify(CorbExpectations expectations,
              const std::string& expected_resource_body) {
    if (0 != (expectations & kShouldBeBlocked)) {
      ASSERT_EQ(net::OK, completion_status().error_code);

      // Verify that the body is empty.
      EXPECT_EQ("", response_body());
      EXPECT_EQ(0, completion_status().decoded_body_length);

      // Verify that other response parts have been sanitized.
      EXPECT_EQ(0u, response_head()->content_length);
      const std::string& headers = response_head()->headers->raw_headers();
      EXPECT_THAT(headers, Not(HasSubstr("Content-Length")));
      EXPECT_THAT(headers, Not(HasSubstr("Content-Type")));

      // Verify that the console message would have been printed.
      EXPECT_TRUE(completion_status().should_report_corb_blocking);
    } else {
      ASSERT_EQ(net::OK, completion_status().error_code);
      EXPECT_FALSE(completion_status().should_report_corb_blocking);
      EXPECT_EQ(expected_resource_body, response_body());
    }
  }

  void InjectRequestInitiator(const url::Origin& request_initiator) {
    request_initiator_to_inject_ = request_initiator;
  }

  void InjectFetchMode(network::mojom::RequestMode request_mode) {
    request_mode_to_inject_ = request_mode;
  }

 private:
  void ReadBody(base::OnceClosure completion_callback) {
    char buffer[128];
    uint32_t num_bytes = sizeof(buffer);
    MojoResult result = test_client_.response_body().ReadData(
        buffer, &num_bytes, MOJO_READ_DATA_FLAG_NONE);

    bool got_all_data = false;
    switch (result) {
      case MOJO_RESULT_OK:
        if (num_bytes != 0) {
          body_ += std::string(buffer, num_bytes);
          got_all_data = false;
        } else {
          got_all_data = true;
        }
        break;
      case MOJO_RESULT_SHOULD_WAIT:
        // There is no data to be read or discarded (and the producer is still
        // open).
        got_all_data = false;
        break;
      case MOJO_RESULT_FAILED_PRECONDITION:
        // The data pipe producer handle has been closed.
        got_all_data = true;
        break;
      default:
        CHECK(false) << "Unexpected mojo error: " << result;
        got_all_data = true;
        break;
    }

    if (!got_all_data) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::BindOnce(&RequestInterceptor::ReadBody, base::Unretained(this),
                         std::move(completion_callback)));
    } else {
      std::move(completion_callback).Run();
    }
  }

  bool InterceptorCallback(URLLoaderInterceptor::RequestParams* params) {
    DCHECK(params);

    if (url_to_intercept_ != params->url_request.url)
      return false;

    // Prevent more than one intercept.
    if (request_intercepted_)
      return false;
    request_intercepted_ = true;
    interceptor_task_runner_ = base::ThreadTaskRunnerHandle::Get();

    // Modify |params| if requested.
    if (request_initiator_to_inject_.has_value())
      params->url_request.request_initiator = request_initiator_to_inject_;
    if (request_mode_to_inject_.has_value())
      params->url_request.mode = request_mode_to_inject_.value();

    // Inject |test_client_| into the request.
    DCHECK(!original_client_);
    original_client_ = std::move(params->client);
    test_client_remote_.Bind(std::move(pending_test_client_remote_));
    test_client_receiver_ =
        std::make_unique<mojo::Receiver<network::mojom::URLLoaderClient>>(
            test_client_remote_.get(),
            params->client.BindNewPipeAndPassReceiver());

    // Forward the request to the original URLLoaderFactory.
    return false;
  }

  void WaitForCleanUpOnInterceptorThread(
      network::mojom::URLResponseHeadPtr response_head,
      std::string response_body,
      network::URLLoaderCompletionStatus status) {
    DCHECK_CURRENTLY_ON(BrowserThread::UI);

    if (cleanup_done_)
      return;

    if (interceptor_task_runner_) {
      base::RunLoop run_loop;
      interceptor_task_runner_->PostTaskAndReply(
          FROM_HERE,
          base::BindOnce(&RequestInterceptor::CleanUpOnInterceptorThread,
                         base::Unretained(this), std::move(response_head),
                         response_body, status),
          run_loop.QuitClosure());
      run_loop.Run();
    }

    cleanup_done_ = true;
  }

  void CleanUpOnInterceptorThread(
      network::mojom::URLResponseHeadPtr response_head,
      std::string response_body,
      network::URLLoaderCompletionStatus status) {
    if (!request_intercepted_)
      return;

    // Tell the |original_client_| that the request has completed (and that it
    // can release its URLLoaderClient.
    if (status.error_code == net::OK) {
      original_client_->OnReceiveResponse(std::move(response_head));

      mojo::DataPipe empty_data_pipe(response_body.size() + 1);
      original_client_->OnStartLoadingResponseBody(
          std::move(empty_data_pipe.consumer_handle));

      uint32_t num_bytes = response_body.size();
      EXPECT_EQ(MOJO_RESULT_OK, empty_data_pipe.producer_handle->WriteData(
                                    response_body.data(), &num_bytes,
                                    MOJO_WRITE_DATA_FLAG_ALL_OR_NONE));
    }
    original_client_->OnComplete(status);

    // Reset all temporary mojo bindings.
    original_client_.reset();
    test_client_receiver_.reset();
    test_client_remote_.reset();
  }

  const GURL url_to_intercept_;
  URLLoaderInterceptor interceptor_;

  base::Optional<url::Origin> request_initiator_to_inject_;
  base::Optional<network::mojom::RequestMode> request_mode_to_inject_;

  // |pending_test_client_remote_| below is used to transition results of
  // |test_client_.CreateRemote()| into IO thread.
  mojo::PendingRemote<network::mojom::URLLoaderClient>
      pending_test_client_remote_;

  // UI thread state:
  network::TestURLLoaderClient test_client_;
  std::string body_;
  bool request_completed_ = false;
  bool cleanup_done_ = false;

  // Interceptor thread state:
  mojo::Remote<network::mojom::URLLoaderClient> original_client_;
  bool request_intercepted_ = false;
  scoped_refptr<base::SingleThreadTaskRunner> interceptor_task_runner_;
  mojo::Remote<network::mojom::URLLoaderClient> test_client_remote_;
  std::unique_ptr<mojo::Receiver<network::mojom::URLLoaderClient>>
      test_client_receiver_;

  DISALLOW_COPY_AND_ASSIGN(RequestInterceptor);
};

}  // namespace

// These tests verify that the browser process blocks cross-site HTML, XML,
// JSON, and some plain text responses when they are not otherwise permitted
// (e.g., by CORS).  This ensures that such responses never end up in the
// renderer process where they might be accessible via a bug.  Careful attention
// is paid to allow other cross-site resources necessary for rendering,
// including cases that may be mislabeled as blocked MIME type.
class CrossSiteDocumentBlockingTestBase : public ContentBrowserTest {
 public:
  CrossSiteDocumentBlockingTestBase() = default;
  ~CrossSiteDocumentBlockingTestBase() override = default;

  void SetUpCommandLine(base::CommandLine* command_line) override {
    // EmbeddedTestServer::InitializeAndListen() initializes its |base_url_|
    // which is required below. This cannot invoke Start() however as that kicks
    // off the "EmbeddedTestServer IO Thread" which then races with
    // initialization in ContentBrowserTest::SetUp(), http://crbug.com/674545.
    // Additionally the server should not be started prior to setting up
    // ControllableHttpResponse(s) in some individual tests below.
    ASSERT_TRUE(embedded_test_server()->InitializeAndListen());

    // Add a host resolver rule to map all outgoing requests to the test server.
    // This allows us to use "real" hostnames and standard ports in URLs (i.e.,
    // without having to inject the port number into all URLs), which we can use
    // to create arbitrary SiteInstances.
    command_line->AppendSwitchASCII(
        network::switches::kHostResolverRules,
        "MAP * " + embedded_test_server()->host_port_pair().ToString() +
            ",EXCLUDE localhost");
  }

  void VerifyImgRequest(std::string resource, CorbExpectations expectations) {
    // Test from a http: origin.
    VerifyImgRequest(resource, expectations,
                     GURL("http://foo.com/title1.html"));

    // Test from a file: origin.
    VerifyImgRequest(resource, expectations,
                     GetTestUrl(nullptr, "title1.html"));
  }

  void VerifyImgRequest(std::string resource,
                        CorbExpectations expectations,
                        GURL page_url) {
    GURL resource_url(
        std::string("http://cross-origin.com/site_isolation/" + resource));
    SCOPED_TRACE(
        base::StringPrintf("... while testing via <img src='%s'> from %s",
                           resource_url.spec().c_str(),
                           url::Origin::Create(page_url).Serialize().c_str()));

    // Navigate to the test page while request interceptor is active.
    RequestInterceptor interceptor(resource_url);
    EXPECT_TRUE(NavigateToURL(shell(), page_url));

    // Make sure that base::HistogramTester below starts with a clean slate.
    FetchHistogramsFromChildProcesses();

    // Issue the request that will be intercepted.
    base::HistogramTester histograms;
    const char kScriptTemplate[] = R"(
        var img = document.createElement('img');
        img.src = $1;
        document.body.appendChild(img); )";
    EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, resource_url)));
    interceptor.WaitForRequestCompletion();

    // Verify...
    InspectHistograms(histograms, expectations, resource,
                      blink::mojom::ResourceType::kImage);
    interceptor.Verify(expectations,
                       GetTestFileContents("site_isolation", resource.c_str()));
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CrossSiteDocumentBlockingTestBase);
};

enum class TestMode {
  kWithCORBProtectionSniffing,
  kWithoutCORBProtectionSniffing,
};
class CrossSiteDocumentBlockingTest
    : public CrossSiteDocumentBlockingTestBase,
      public testing::WithParamInterface<TestMode> {
 public:
  CrossSiteDocumentBlockingTest() {
    switch (GetParam()) {
      case TestMode::kWithCORBProtectionSniffing:
        scoped_feature_list_.InitAndEnableFeature(
            network::features::kCORBProtectionSniffing);
        break;
      case TestMode::kWithoutCORBProtectionSniffing:
        scoped_feature_list_.InitAndDisableFeature(
            network::features::kCORBProtectionSniffing);
        break;
    }
  }
  ~CrossSiteDocumentBlockingTest() override = default;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(CrossSiteDocumentBlockingTest);
};

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, BlockImagesWithSniffing) {
  embedded_test_server()->StartAcceptingConnections();

  // The following are files under content/test/data/site_isolation. All
  // should be disallowed for cross site XHR under the document blocking policy.
  //   valid.*        - Correctly labeled HTML/XML/JSON files.
  //   *.txt          - Plain text that sniffs as HTML, XML, or JSON.
  //   htmlN_dtd.*    - Various HTML templates to test.
  //   json-prefixed* - parser-breaking prefixes
  const char* blocked_resources[] = {"valid.html",
                                     "valid.xml",
                                     "valid.json",
                                     "html.txt",
                                     "xml.txt",
                                     "json.txt",
                                     "comment_valid.html",
                                     "html4_dtd.html",
                                     "html4_dtd.txt",
                                     "html5_dtd.html",
                                     "html5_dtd.txt",
                                     "json.js",
                                     "json-prefixed-1.js",
                                     "json-prefixed-2.js",
                                     "json-prefixed-3.js",
                                     "json-prefixed-4.js",
                                     "nosniff.json.js",
                                     "nosniff.json-prefixed.js"};
  for (const char* resource : blocked_resources)
    VerifyImgRequest(resource, kShouldBeSniffedAndBlocked);
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, BlockImagesNoSniffing) {
  embedded_test_server()->StartAcceptingConnections();

  // These files should be disallowed without sniffing.
  //   nosniff.*   - Won't sniff correctly, but blocked because of nosniff.
  const char* nosniff_blocked_resources[] = {"nosniff.html", "nosniff.xml",
                                             "nosniff.json", "nosniff.txt",
                                             "fake.pdf",     "fake.zip"};
  for (const char* resource : nosniff_blocked_resources)
    VerifyImgRequest(resource, kShouldBeBlockedWithoutSniffing);
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, AllowImagesWithSniffing) {
  embedded_test_server()->StartAcceptingConnections();

  // These files are allowed for XHR under the document blocking policy because
  // the sniffing logic determines they are not actually documents.
  //   *js.*   - JavaScript mislabeled as a document.
  //   jsonp.* - JSONP (i.e., script) mislabeled as a document.
  //   img.*   - Contents that won't match the document label.
  //   valid.* - Correctly labeled responses of non-document types.
  const char* sniff_allowed_resources[] = {"html-prefix.txt",
                                           "js.html",
                                           "comment_js.html",
                                           "js.xml",
                                           "js.json",
                                           "js.txt",
                                           "jsonp.html",
                                           "jsonp.xml",
                                           "jsonp.json",
                                           "jsonp.txt",
                                           "img.html",
                                           "img.xml",
                                           "img.json",
                                           "img.txt",
                                           "valid.js",
                                           "json-list.js",
                                           "nosniff.json-list.js",
                                           "js-html-polyglot.html",
                                           "js-html-polyglot2.html"};
  for (const char* resource : sniff_allowed_resources)
    VerifyImgRequest(resource, kShouldBeSniffedAndAllowed);
}

// This test covers an aspect of Cross-Origin-Resource-Policy (CORP, different
// from CORB) that cannot be covered by wpt/fetch/cross-origin-resource-policy:
// whether blocking occurs *before* the response reaches the renderer process.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       CrossOriginResourcePolicy) {
  embedded_test_server()->StartAcceptingConnections();

  // Navigate to the test page while request interceptor is active.
  GURL resource_url("http://cross-origin.com/site_isolation/png-corp.png");
  RequestInterceptor interceptor(resource_url);
  EXPECT_TRUE(NavigateToURL(shell(), GURL("http://foo.com/title1.html")));

  // Issue the request that will be intercepted.
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, resource_url)));
  interceptor.WaitForRequestCompletion();

  // Verify that Cross-Origin-Resource-Policy blocked the response before it
  // reached the renderer process.
  EXPECT_EQ(net::ERR_BLOCKED_BY_RESPONSE,
            interceptor.completion_status().error_code);
  EXPECT_EQ("", interceptor.response_body());
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, AllowCorsFetches) {
  embedded_test_server()->StartAcceptingConnections();
  GURL foo_url("http://foo.com/cross_site_document_blocking/request.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // These files should be allowed for XHR under the document blocking policy.
  //   cors.*  - Correctly labeled documents with valid CORS headers.
  const char* allowed_resources[] = {"cors.html", "cors.xml", "cors.json",
                                     "cors.txt"};
  for (const char* resource : allowed_resources) {
    SCOPED_TRACE(base::StringPrintf("... while testing page: %s", resource));

    // Make sure that base::HistogramTester below starts with a clean slate.
    FetchHistogramsFromChildProcesses();

    // Fetch.
    base::HistogramTester histograms;
    bool was_blocked;
    ASSERT_TRUE(ExecuteScriptAndExtractBool(
        shell(), base::StringPrintf("sendRequest('%s');", resource),
        &was_blocked));

    // Verify results of the fetch.
    EXPECT_FALSE(was_blocked);
    InspectHistograms(histograms, kShouldBeAllowedWithoutSniffing, resource,
                      blink::mojom::ResourceType::kXhr);
  }
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       AllowSameOriginFetchFromLoadDataWithBaseUrl) {
  embedded_test_server()->StartAcceptingConnections();

  // LoadDataWithBaseURL is never subject to --site-per-process policy today
  // (this API is only used by Android WebView [where OOPIFs have not shipped
  // yet] and GuestView cases [which always hosts guests inside a renderer
  // without an origin lock]).  Therefore, skip the test in --site-per-process
  // mode to avoid renderer kills which won't happen in practice as described
  // above.
  //
  // TODO(https://crbug.com/962643): Consider enabling this test once Android
  // Webview or WebView guests support OOPIFs and/or origin locks.
  if (AreAllSitesIsolatedForTesting())
    return;

  // Navigate via LoadDataWithBaseURL.
  const GURL base_url("http://foo.com");
  const std::string data = "<html><body>foo</body></html>";
  const GURL data_url = GURL("data:text/html;charset=utf-8," + data);
  TestNavigationObserver nav_observer(shell()->web_contents(), 1);
  shell()->LoadDataWithBaseURL(base_url /* history_url */, data, base_url);
  nav_observer.Wait();

  // Fetch a same-origin resource.
  GURL resource_url("http://foo.com/site_isolation/nosniff.html");
  EXPECT_EQ(url::Origin::Create(resource_url),
            shell()->web_contents()->GetMainFrame()->GetLastCommittedOrigin());
  FetchHistogramsFromChildProcesses();
  base::HistogramTester histograms;
  std::string fetch_result =
      EvalJs(shell(), JsReplace("fetch($1).then(response => response.text())",
                                resource_url))
          .ExtractString();
  fetch_result = TrimWhitespaceASCII(fetch_result, base::TRIM_ALL).as_string();

  // Verify that the response was not blocked.
  EXPECT_EQ("runMe({ \"name\" : \"chromium\" });", fetch_result);
  InspectHistograms(histograms, kShouldBeAllowedWithoutSniffing, "nosniff.html",
                    blink::mojom::ResourceType::kXhr);
}

// Regression test for https://crbug.com/958421.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, BackToAboutBlank) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to verify results of a fetch.
  GURL resource_url("http://foo.com/title2.html");
  const char* resource = "title2.html";
  const char kFetchScriptTemplate[] = R"(
      fetch($1, {mode: 'no-cors'}).then(response => 'ok');
  )";
  std::string fetch_script = JsReplace(kFetchScriptTemplate, resource_url);

  // Navigate to the test page and open a popup via |window.open|, explicitly
  // specifying 'about:blank' destination, so that we can go back to it later.
  GURL initial_url("http://foo.com/title1.html");
  EXPECT_TRUE(NavigateToURL(shell(), initial_url));
  WebContentsAddedObserver popup_observer;
  ASSERT_TRUE(ExecJs(shell(), "var popup = window.open('about:blank', '')"));
  WebContents* popup = popup_observer.GetWebContents();
  EXPECT_EQ(GURL(url::kAboutBlankURL),
            popup->GetMainFrame()->GetLastCommittedURL());
  EXPECT_EQ(shell()->web_contents()->GetMainFrame()->GetLastCommittedOrigin(),
            popup->GetMainFrame()->GetLastCommittedOrigin());
  EXPECT_EQ(url::Origin::Create(resource_url),
            popup->GetMainFrame()->GetLastCommittedOrigin());

  // Verify that CORB doesn't block same-origin request from the popup.
  {
    FetchHistogramsFromChildProcesses();
    base::HistogramTester histograms;
    ASSERT_EQ("ok", EvalJs(popup, fetch_script));
    InspectHistograms(histograms, kShouldBeAllowedWithoutSniffing, resource,
                      blink::mojom::ResourceType::kXhr);
  }

  // Navigate the popup and then go back to the 'about:blank' URL.
  TestNavigationObserver nav_observer(popup);
  ASSERT_TRUE(ExecJs(shell(), "popup.location.href = '/title3.html'"));
  nav_observer.WaitForNavigationFinished();
  TestNavigationObserver back_observer(popup);
  ASSERT_TRUE(ExecJs(shell(), "popup.history.back()"));
  back_observer.WaitForNavigationFinished();
  EXPECT_EQ(GURL(url::kAboutBlankURL),
            popup->GetMainFrame()->GetLastCommittedURL());
  EXPECT_EQ(shell()->web_contents()->GetMainFrame()->GetLastCommittedOrigin(),
            popup->GetMainFrame()->GetLastCommittedOrigin());
  EXPECT_EQ(url::Origin::Create(resource_url),
            popup->GetMainFrame()->GetLastCommittedOrigin());

  // Verify that CORB doesn't block same-origin request from the popup.
  {
    FetchHistogramsFromChildProcesses();
    base::HistogramTester histograms;
    ASSERT_EQ("ok", EvalJs(popup, fetch_script));
    InspectHistograms(histograms, kShouldBeAllowedWithoutSniffing, resource,
                      blink::mojom::ResourceType::kXhr);
  }
}

#if defined(OS_ANDROID)
// Test is flaky on Android, see crbug.com/1075663
#define MAYBE_BlockForVariousTargets DISABLED_BlockForVariousTargets
#else
#define MAYBE_BlockForVariousTargets BlockForVariousTargets
#endif
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       MAYBE_BlockForVariousTargets) {
  // This webpage loads a cross-site HTML page in different targets such as
  // <img>,<link>,<embed>, etc. Since the requested document is blocked, and one
  // character string (' ') is returned instead, this tests that the renderer
  // does not crash even when it receives a response body which is " ", whose
  // length is different from what's described in "content-length" for such
  // different targets.

  // TODO(nick): Split up these cases, and add positive assertions here about
  // what actually happens in these various resource-block cases.
  embedded_test_server()->StartAcceptingConnections();
  GURL foo("http://foo.com/cross_site_document_blocking/request_target.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo));

  // TODO(creis): Wait for all the subresources to load and ensure renderer
  // process is still alive.
}

// Checks to see that CORB blocking applies to processes hosting error pages.
// Regression test for https://crbug.com/814913.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       BlockRequestFromErrorPage) {
  embedded_test_server()->StartAcceptingConnections();
  GURL error_url = embedded_test_server()->GetURL("bar.com", "/close-socket");
  GURL subresource_url =
      embedded_test_server()->GetURL("foo.com", "/site_isolation/json.js");

  // Load |error_url| and expect a network error page.
  TestNavigationObserver observer(shell()->web_contents());
  EXPECT_FALSE(NavigateToURL(shell(), error_url));
  EXPECT_EQ(error_url, observer.last_navigation_url());
  NavigationEntry* entry =
      shell()->web_contents()->GetController().GetLastCommittedEntry();
  EXPECT_EQ(PAGE_TYPE_ERROR, entry->GetPageType());

  // Add a <script> tag whose src is a CORB-protected resource. Expect no
  // window.onerror to result, because no syntax error is generated by the empty
  // response.
  std::string script = R"((subresource_url => {
    window.onerror = () => domAutomationController.send("CORB BYPASSED");
    var script = document.createElement('script');
    script.src = subresource_url;
    script.onload = () => domAutomationController.send("CORB WORKED");
    document.body.appendChild(script);
    }))";
  std::string result;
  ASSERT_TRUE(ExecuteScriptAndExtractString(
      shell(), script + "('" + subresource_url.spec() + "')", &result));

  EXPECT_EQ("CORB WORKED", result);
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       HeadersBlockedInResponseBlockedByCorb) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to intercept the network request at the IPC layer.
  // This has to be done before the RenderFrameHostImpl is created.
  //
  // Note: we want to verify that the blocking prevents the data from being sent
  // over IPC.  Testing later (e.g. via Response/Headers Web APIs) might give a
  // false sense of security, since some sanitization happens inside the
  // renderer (e.g. via FetchResponseData::CreateCorsFilteredResponse).
  GURL bar_url("http://bar.com/cross_site_document_blocking/headers-test.json");
  RequestInterceptor interceptor(bar_url);

  // Navigate to the test page.
  GURL foo_url("http://foo.com/title1.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // Issue the request that will be intercepted.
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, bar_url)));
  interceptor.WaitForRequestCompletion();

  // Verify that the response completed successfully, was blocked and was logged
  // as having initially a non-empty body.
  interceptor.Verify(kShouldBeBlockedWithoutSniffing,
                     "no resource body needed for blocking verification");

  // Verify that most response headers have been removed by CORB.
  const std::string& headers =
      interceptor.response_head()->headers->raw_headers();
  EXPECT_THAT(headers, HasSubstr("Access-Control-Allow-Origin: https://other"));
  EXPECT_THAT(headers, Not(HasSubstr("Cache-Control")));
  EXPECT_THAT(headers, Not(HasSubstr("Content-Language")));
  EXPECT_THAT(headers, Not(HasSubstr("Content-Length")));
  EXPECT_THAT(headers, Not(HasSubstr("Content-Type")));
  EXPECT_THAT(headers, Not(HasSubstr("Expires")));
  EXPECT_THAT(headers, Not(HasSubstr("Last-Modified")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieKey")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieValue")));
  EXPECT_THAT(headers, Not(HasSubstr("Pragma")));
  EXPECT_THAT(headers, Not(HasSubstr("X-Content-Type-Options")));
  EXPECT_THAT(headers, Not(HasSubstr("X-My-Secret-Header")));

  // Verify that the body is empty.
  EXPECT_EQ("", interceptor.response_body());
  EXPECT_EQ(0, interceptor.completion_status().decoded_body_length);

  // Verify that other response parts have been sanitized.
  EXPECT_EQ(0u, interceptor.response_head()->content_length);
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       HeadersSanitizedInCrossOriginResponseAllowedByCorb) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to intercept the network request at the IPC layer.
  // This has to be done before the RenderFrameHostImpl is created.
  //
  // Note: we want to verify that the blocking prevents the data from being sent
  // over IPC.  Testing later (e.g. via Response/Headers Web APIs) might give a
  // false sense of security, since some sanitization happens inside the
  // renderer (e.g. via FetchResponseData::CreateCorsFilteredResponse).
  GURL bar_url("http://bar.com/cross_site_document_blocking/headers-test.png");
  RequestInterceptor interceptor(bar_url);
  std::string png_body =
      GetTestFileContents("cross_site_document_blocking", "headers-test.png");

  // Navigate to the test page.
  GURL foo_url("http://foo.com/title1.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // Issue the request that will be intercepted.
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, bar_url)));
  interceptor.WaitForRequestCompletion();

  // Verify that the response completed successfully, was blocked and was logged
  // as having initially a non-empty body.
  interceptor.Verify(kShouldBeSniffedAndAllowed, png_body);

  // Verify that most response headers have been allowed by CORB.
  const std::string& headers =
      interceptor.response_head()->headers->raw_headers();
  EXPECT_THAT(headers, HasSubstr("Cache-Control"));
  EXPECT_THAT(headers, HasSubstr("Content-Length"));
  EXPECT_THAT(headers, HasSubstr("Content-Type"));
  EXPECT_THAT(headers, HasSubstr("Expires"));
  EXPECT_THAT(headers, HasSubstr("Last-Modified"));
  EXPECT_THAT(headers, HasSubstr("Pragma"));
  EXPECT_THAT(headers, HasSubstr("X-Content-Type-Options"));
  EXPECT_THAT(headers, HasSubstr("X-My-Secret-Header"));

  // Verify that the body has been allowed by CORB.
  EXPECT_EQ(png_body, interceptor.response_body());
  EXPECT_EQ(static_cast<int64_t>(png_body.size()),
            interceptor.completion_status().decoded_body_length);
  EXPECT_EQ(static_cast<int64_t>(png_body.size()),
            interceptor.response_head()->content_length);

  // MAIN VERIFICATION: Verify that despite allowing the response in CORB, we
  // stripped out the cookies (i.e. the cookies present in
  // cross_site_document_blocking/headers-test.png.mock-http-headers).
  //
  // This verification helps ensure that no cross-origin secrets are disclosed
  // in no-cors responses.
  EXPECT_THAT(headers, Not(HasSubstr("MySecretPlainCookieKey")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieValue1")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretHttpOnlyCookieKey")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieValue2")));
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       HeadersSanitizedInSameOriginResponseAllowedByCorb) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to intercept the network request at the IPC layer.
  // This has to be done before the RenderFrameHostImpl is created.
  //
  // Note: we want to verify that the blocking prevents the data from being sent
  // over IPC.  Testing later (e.g. via Response/Headers Web APIs) might give a
  // false sense of security, since some sanitization happens inside the
  // renderer (e.g. via FetchResponseData::CreateCorsFilteredResponse).
  GURL foo_resource_url(
      "http://foo.com/cross_site_document_blocking/headers-test.png");
  RequestInterceptor interceptor(foo_resource_url);
  std::string png_body =
      GetTestFileContents("cross_site_document_blocking", "headers-test.png");

  // Navigate to the test page.
  GURL foo_url("http://foo.com/title1.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // Issue the request that will be intercepted.
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, foo_resource_url)));
  interceptor.WaitForRequestCompletion();

  // Verify that the response completed successfully, was blocked and was logged
  // as having initially a non-empty body.
  interceptor.Verify(kShouldBeSniffedAndAllowed, png_body);

  // Verify that most response headers have been allowed by CORB.
  const std::string& headers =
      interceptor.response_head()->headers->raw_headers();
  EXPECT_THAT(headers, HasSubstr("Cache-Control"));
  EXPECT_THAT(headers, HasSubstr("Content-Length"));
  EXPECT_THAT(headers, HasSubstr("Content-Type"));
  EXPECT_THAT(headers, HasSubstr("Expires"));
  EXPECT_THAT(headers, HasSubstr("Last-Modified"));
  EXPECT_THAT(headers, HasSubstr("Pragma"));
  EXPECT_THAT(headers, HasSubstr("X-Content-Type-Options"));
  EXPECT_THAT(headers, HasSubstr("X-My-Secret-Header"));

  // Verify that the body has been allowed by CORB.
  EXPECT_EQ(png_body, interceptor.response_body());
  EXPECT_EQ(static_cast<int64_t>(png_body.size()),
            interceptor.completion_status().decoded_body_length);
  EXPECT_EQ(static_cast<int64_t>(png_body.size()),
            interceptor.response_head()->content_length);

  // MAIN VERIFICATION: Verify that despite allowing the response in CORB, we
  // stripped out the cookies (i.e. the cookies present in
  // cross_site_document_blocking/headers-test.png.mock-http-headers).
  //
  // No security boundary is crossed in this test case (since this is a
  // same-origin response), but for consistency we want to ensure that cookies
  // are stripped in all IPCs.
  EXPECT_THAT(headers, Not(HasSubstr("MySecretPlainCookieKey")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieValue1")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretHttpOnlyCookieKey")));
  EXPECT_THAT(headers, Not(HasSubstr("MySecretCookieValue2")));
}

// TODO(lukasza): https://crbug.com/154571: Enable this test on Android once
// SharedWorkers are also enabled on Android.
#if !defined(OS_ANDROID)
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, SharedWorker) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to intercept the network request at the IPC layer.
  // This has to be done before the SharedWorkerHost is created.
  GURL bar_url("http://bar.com/site_isolation/nosniff.json");
  RequestInterceptor interceptor(bar_url);

  // Navigate to the test page.
  GURL foo_url("http://foo.com/title1.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  // Start a shared worker and wait until it says that it is ready.
  const char kWorkerScriptTemplate[] = R"(
      onconnect = function(e) {
        const port = e.ports[0];

        port.addEventListener('message', function(e) {
          url = e.data;
          fetch(url, {mode: 'no-cors'})
              .then(_ => port.postMessage('FETCH SUCCEEDED'))
              .catch(e => port.postMessage('FETCH ERROR: ' + e));
        });

        port.start();
        port.postMessage('WORKER READY');
      };
  )";
  std::string worker_script;
  base::Base64Encode(JsReplace(kWorkerScriptTemplate, bar_url), &worker_script);
  const char kWorkerStartTemplate[] = R"(
      new Promise(function (resolve, reject) {
          const worker_url = 'data:application/javascript;base64,' + $1;
          window.myWorker = new SharedWorker(worker_url);
          window.myWorkerMessageHandler = resolve;
          window.myWorker.port.onmessage = function(e) {
              window.myWorkerMessageHandler(e.data);
          };
      });
  )";
  EXPECT_EQ("WORKER READY",
            EvalJs(shell(), JsReplace(kWorkerStartTemplate, worker_script)));

  // Make sure that base::HistogramTester below starts with a clean slate.
  FetchHistogramsFromChildProcesses();
  base::HistogramTester histograms;

  // Ask the shared worker to perform a cross-origin fetch.
  const char kFetchStartTemplate[] = R"(
      const fetch_url = $1;
      window.myWorkerMessageHandler = function(data) {
          window.myWorkerResult = data;
      }
      window.myWorker.port.postMessage(fetch_url);
  )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kFetchStartTemplate, bar_url)));

  interceptor.WaitForRequestCompletion();
  interceptor.Verify(kShouldBeBlockedWithoutSniffing,
                     "no resource body needed for blocking verification");

  // Wait for fetch result (really needed only without NetworkService, if no
  // interceptor.WaitForRequestCompletion was called above).
  const char kFetchWait[] = R"(
      new Promise(function (resolve, reject) {
          if (window.myWorkerResult) {
            resolve(window.myWorkerResult);
            return;
          }
          window.myWorkerMessageHandler = resolve;
      });
  )";
  EXPECT_EQ("FETCH SUCCEEDED", EvalJs(shell(), kFetchWait));

  // Verify that the response completed successfully, was blocked and was logged
  // as having initially a non-empty body.
  InspectHistograms(histograms, kShouldBeBlockedWithoutSniffing, "nosniff.json",
                    blink::mojom::ResourceType::kXhr);
}
#endif  // !defined(OS_ANDROID)

// Tests what happens in a page covered by AppCache (where the AppCache manifest
// doesn't cover any cross-origin resources).  In particular, requests from the
// web page that get proxied by the AppCache to the network (falling back to the
// network because they are not covered by the AppCache manifest) should still
// be subject to CORB.
// TODO(crbug.com/1030837): re-enable test once flakiness is addressed.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       DISABLED_AppCache_NetworkFallback) {
  embedded_test_server()->StartAcceptingConnections();

  // Prepare to intercept the network request at the IPC layer.
  // This has to be done before the RenderFrameHostImpl is created.
  GURL cross_site_url("http://cross-origin.com/site_isolation/nosniff.json");
  RequestInterceptor interceptor(cross_site_url);

  // Set up a separate http server, to allow sanity-checking that AppCache
  // serves files despite the fact that the original server is down.
  net::EmbeddedTestServer app_cache_content_server;
  app_cache_content_server.AddDefaultHandlers(GetTestDataFilePath());
  ASSERT_TRUE(app_cache_content_server.Start());

  // Load the main page twice. The second navigation should have AppCache
  // initialized for the page.
  GURL main_url = app_cache_content_server.GetURL(
      "/appcache/simple_page_with_manifest.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  base::string16 expected_title = base::ASCIIToUTF16("AppCache updated");
  content::TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Turn off the server and sanity check that the resource is still available
  // (because of AppCache).
  ASSERT_TRUE(app_cache_content_server.ShutdownAndWaitUntilComplete());
  {
    const char kScriptTemplate[] = R"(
        new Promise(function (resolve, reject) {
            var img = document.createElement('img');
            img.src = '/appcache/' + $1;
            img.onload = _ => resolve('IMG LOADED');
            img.onerror = reject;
        })
    )";
    EXPECT_EQ("IMG LOADED",
              content::EvalJs(shell(),
                              content::JsReplace(kScriptTemplate, "logo.png")));
  }

  // Verify that CORB also works in presence of AppCache.
  {
    // Make sure that base::HistogramTester below starts with a clean slate.
    FetchHistogramsFromChildProcesses();

    // Fetch...
    base::HistogramTester histograms;
    const char kScriptTemplate[] = R"(
        var img = document.createElement('img');
        img.src = $1;
        document.body.appendChild(img); )";
    EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, cross_site_url)));
    interceptor.WaitForRequestCompletion();

    // Verify...
    bool special_request_initiator_origin_lock_check_for_appcache = true;
    InspectHistograms(histograms, kShouldBeBlockedWithoutSniffing,
                      "nosniff.json", blink::mojom::ResourceType::kImage,
                      special_request_initiator_origin_lock_check_for_appcache);
    interceptor.Verify(kShouldBeBlockedWithoutSniffing,
                       "no resource body needed for blocking verification");
  }
}

// Tests what happens in a page covered by AppCache, where the AppCache manifest
// covers cross-origin resources.  In this case the cross-origin resource
// requests will be triggered by AppCache-manifest-processing code (rather than
// triggered directly by the web page / renderer process as in
// AppCache_NetworkFallback).  Such manifest-triggered requests need to be
// subject to CORB.
//
// This is a regression test for https://crbug.com/927471.
// TODO(crbug.com/1030837): re-enable test once flakiness is addressed.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       DISABLED_AppCache_InManifest) {
  embedded_test_server()->StartAcceptingConnections();

  // Load the AppCached page and wait until the AppCache is populated (this will
  // include the cross-origin
  // http://cross-origin.com/site_isolation/nosniff.json from
  // site_isolation/appcached_cross_origin_resource.manifest.
  base::HistogramTester histograms;
  GURL main_url = embedded_test_server()->GetURL(
      "/site_isolation/appcached_cross_origin_resource.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  base::string16 expected_title = base::ASCIIToUTF16("AppCache updated");
  content::TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());

  // Verify that the request for nosniff.json was covered by CORB.
  FetchHistogramsFromChildProcesses();
  EXPECT_EQ(1, histograms.GetBucketCount(
                   "SiteIsolation.XSD.Browser.Action",
                   static_cast<int>(Action::kBlockedWithoutSniffing)));
}

// Tests that renderer will be terminated if it asks AppCache to initiate a
// request with an invalid |request_initiator|.
// TODO(crbug.com/1030837): re-enable test once flakiness is addressed.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       DISABLED_AppCache_InitiatorEnforcement) {
  embedded_test_server()->StartAcceptingConnections();

  // No kills are expected unless the fetch requesting process is locked to a
  // specific site URL.  Therefore, the test should be skipped unless the full
  // Site Isolation is enabled.
  if (!AreAllSitesIsolatedForTesting())
    return;

  // Prepare to intercept the network request at the IPC layer in a way, that
  // injects |spoofed_initiator| (simulating a compromised renderer that
  // pretends to be making the request on behalf of another origin).
  //
  // Note that RequestInterceptor has to be constructed before the
  // RenderFrameHostImpl is created.
  GURL cross_site_url("http://cross-origin.com/site_isolation/nosniff.json");
  RequestInterceptor interceptor(cross_site_url);
  url::Origin spoofed_initiator =
      url::Origin::Create(GURL("https://victim.example.com"));
  interceptor.InjectRequestInitiator(spoofed_initiator);

  // Load the main page twice. The second navigation should have AppCache
  // initialized for the page.
  GURL main_url = embedded_test_server()->GetURL(
      "/appcache/simple_page_with_manifest.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  base::string16 expected_title = base::ASCIIToUTF16("AppCache updated");
  content::TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Trigger an AppCache request with an incorrect |request_initiator| and
  // verify that this will terminate the renderer process.
  //
  // Note that during the test, no renderer processes will be actually
  // terminated, because the malicious/invalid message originates from within
  // the test process (i.e. from URLLoaderInterceptor::Interceptor's
  // CreateLoaderAndStart method which forwards the
  // InjectRequestInitiator-modified request into
  // AppCacheSubresourceURLFactory).  This necessitates testing via
  // mojo::test::BadMessageObserver rather than via RenderProcessHostWatcher or
  // RenderProcessHostBadMojoMessageWaiter.
  mojo::test::BadMessageObserver bad_message_observer;
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, cross_site_url)));
  EXPECT_EQ("APPCACHE_SUBRESOURCE_URL_FACTORY_INVALID_INITIATOR",
            bad_message_observer.WaitForBadMessage());
}

// Tests that renderer will be terminated if it asks AppCache to initiate a
// cross-origin request with network::mojom::RequestMode::kNavigate.
// TODO(crbug.com/1030837): re-enable test once flakiness is addressed.
IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest,
                       DISABLED_AppCache_NoNavigationsEnforcement) {
  embedded_test_server()->StartAcceptingConnections();

  // No kills are expected unless the fetch requesting process is locked to a
  // specific site URL.  Therefore, the test should be skipped unless the full
  // Site Isolation is enabled.
  if (!AreAllSitesIsolatedForTesting())
    return;

  // Prepare to intercept the network request at the IPC layer in a way, that
  // injects a spoofed fetch mode (simulating a compromised renderer that
  // attempts to bypass CORB by using a fetch mode other than no-cors).
  //
  // Note that RequestInterceptor has to be constructed before the
  // RenderFrameHostImpl is created.
  GURL cross_site_url("http://cross-origin.com/site_isolation/nosniff.json");
  RequestInterceptor interceptor(cross_site_url);
  interceptor.InjectFetchMode(network::mojom::RequestMode::kNavigate);

  // Load the main page twice. The second navigation should have AppCache
  // initialized for the page.
  GURL main_url = embedded_test_server()->GetURL(
      "/appcache/simple_page_with_manifest.html");
  EXPECT_TRUE(NavigateToURL(shell(), main_url));
  base::string16 expected_title = base::ASCIIToUTF16("AppCache updated");
  content::TitleWatcher title_watcher(shell()->web_contents(), expected_title);
  EXPECT_EQ(expected_title, title_watcher.WaitAndGetTitle());
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Trigger an AppCache request with an incorrect |request_initiator| and
  // verify that this will terminate the renderer process.
  //
  // Note that during the test, no renderer processes will be actually
  // terminated, because the malicious/invalid message originates from within
  // the test process (i.e. from URLLoaderInterceptor::Interceptor's
  // CreateLoaderAndStart method which forwards the
  // InjectFetchMode-modified request into
  // AppCacheSubresourceURLFactory).  This necessitates testing via
  // mojo::test::BadMessageObserver rather than via RenderProcessHostWatcher or
  // RenderProcessHostBadMojoMessageWaiter.
  mojo::test::BadMessageObserver bad_message_observer;
  const char kScriptTemplate[] = R"(
      var img = document.createElement('img');
      img.src = $1;
      document.body.appendChild(img); )";
  EXPECT_TRUE(ExecJs(shell(), JsReplace(kScriptTemplate, cross_site_url)));
  EXPECT_EQ("APPCACHE_SUBRESOURCE_URL_FACTORY_NAVIGATE",
            bad_message_observer.WaitForBadMessage());
}

IN_PROC_BROWSER_TEST_P(CrossSiteDocumentBlockingTest, PrefetchIsNotImpacted) {
  // Prepare for intercepting the resource request for testing prefetching.
  const char* kPrefetchResourcePath = "/prefetch-test";
  net::test_server::ControllableHttpResponse response(embedded_test_server(),
                                                      kPrefetchResourcePath);

  // Navigate to a webpage containing a cross-origin frame.
  embedded_test_server()->StartAcceptingConnections();
  GURL main_url(embedded_test_server()->GetURL(
      "a.com", "/cross_site_iframe_factory.html?a(b)"));
  EXPECT_TRUE(NavigateToURL(shell(), main_url));

  // Make sure that base::HistogramTester below starts with a clean slate.
  FetchHistogramsFromChildProcesses();

  // Inject a cross-origin <link rel="prefetch" ...> into the main frame.
  // TODO(lukasza): https://crbug.com/827633#c5: We might need to switch to
  // listening to the onload event below (after/if CORB starts to consistently
  // avoid injecting net errors).
  FetchHistogramsFromChildProcesses();
  base::HistogramTester histograms;
  const char* prefetch_injection_script_template = R"(
      var link = document.createElement("link");
      link.rel = "prefetch";
      link.href = "/cross-site/b.com%s";
      link.as = "fetch";

      window.is_prefetch_done = false;
      function mark_prefetch_as_done() { window.is_prefetch_done = true }
      link.onerror = mark_prefetch_as_done;

      document.getElementsByTagName('head')[0].appendChild(link);
  )";
  std::string prefetch_injection_script = base::StringPrintf(
      prefetch_injection_script_template, kPrefetchResourcePath);
  EXPECT_TRUE(
      ExecuteScript(shell()->web_contents(), prefetch_injection_script));

  // Respond to the prefetch request in a way that:
  // 1) will enable caching
  // 2) won't finish until after CORB has blocked the response.
  std::string response_bytes =
      "HTTP/1.1 200 OK\r\n"
      "Cache-Control: public, max-age=10\r\n"
      "Content-Type: text/html\r\n"
      "X-Content-Type-Options: nosniff\r\n"
      "\r\n"
      "<p>contents of the response</p>";
  response.WaitForRequest();
  response.Send(response_bytes);

  // Verify that CORB blocked the response.
  // TODO(lukasza): https://crbug.com/827633#c5: We might need to switch to
  // listening to the onload event below (after/if CORB starts to consistently
  // avoid injecting net errors).
  std::string wait_script = R"(
      function notify_prefetch_is_done() { domAutomationController.send(123); }

      if (window.is_prefetch_done) {
        // Can notify immediately if |window.is_prefetch_done| has already been
        // set by |prefetch_injection_script|.
        notify_prefetch_is_done();
      } else {
        // Otherwise wait for CORB's empty response to reach the renderer.
        link = document.getElementsByTagName('link')[0];
        link.onerror = notify_prefetch_is_done;
      }
  )";
  int answer;
  EXPECT_TRUE(ExecuteScriptAndExtractInt(shell()->web_contents(), wait_script,
                                         &answer));
  EXPECT_EQ(123, answer);
  InspectHistograms(histograms, kShouldBeBlockedWithoutSniffing, "x.html",
                    blink::mojom::ResourceType::kPrefetch);

  // Finish the HTTP response - this should store the response in the cache.
  response.Done();

  // Stop the HTTP server - this means the only way to get the response in
  // the |fetch_script| below is to get it from the cache (e.g. if the request
  // goes to the network there will be no HTTP server to handle it).
  // Note that stopping the HTTP server is not strictly required for the test to
  // be robust - ControllableHttpResponse handles only a single request, so
  // wouldn't handle the |fetch_script| request even if the HTTP server was
  // still running.
  EXPECT_TRUE(embedded_test_server()->ShutdownAndWaitUntilComplete());

  // Verify that the cached response is available to the same-origin subframe
  // (e.g. that the network cache in the browser process got populated despite
  // CORB blocking).
  const char* fetch_script_template = R"(
      fetch('%s')
          .then(response => response.text())
          .then(responseBody => {
              domAutomationController.send(responseBody);
          })
          .catch(error => {
              var errorMessage = 'error: ' + error;
              console.log(errorMessage);
              domAutomationController.send(errorMessage);
          }); )";
  std::string fetch_script =
      base::StringPrintf(fetch_script_template, kPrefetchResourcePath);
  std::string response_body;
  EXPECT_TRUE(
      ExecuteScriptAndExtractString(shell()->web_contents()->GetAllFrames()[1],
                                    fetch_script, &response_body));
  EXPECT_EQ("<p>contents of the response</p>", response_body);
}

INSTANTIATE_TEST_SUITE_P(
    WithCORBProtectionSniffing,
    CrossSiteDocumentBlockingTest,
    ::testing::Values(TestMode::kWithCORBProtectionSniffing));

INSTANTIATE_TEST_SUITE_P(
    WithoutCORBProtectionSniffing,
    CrossSiteDocumentBlockingTest,
    ::testing::Values(TestMode::kWithoutCORBProtectionSniffing));

// This test class sets up a service worker that can be used to try to respond
// to same-origin requests with cross-origin responses.
class CrossSiteDocumentBlockingServiceWorkerTest : public ContentBrowserTest {
 public:
  CrossSiteDocumentBlockingServiceWorkerTest()
      : service_worker_https_server_(net::EmbeddedTestServer::TYPE_HTTPS),
        cross_origin_https_server_(net::EmbeddedTestServer::TYPE_HTTPS) {}
  ~CrossSiteDocumentBlockingServiceWorkerTest() override {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    IsolateAllSitesForTesting(command_line);
    ContentBrowserTest::SetUpCommandLine(command_line);
  }

  void SetUpOnMainThread() override {
    SetupCrossSiteRedirector(embedded_test_server());

    service_worker_https_server_.ServeFilesFromSourceDirectory(
        GetTestDataFilePath());
    ASSERT_TRUE(service_worker_https_server_.Start());

    cross_origin_https_server_.ServeFilesFromSourceDirectory(
        GetTestDataFilePath());
    cross_origin_https_server_.SetSSLConfig(
        net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
    ASSERT_TRUE(cross_origin_https_server_.Start());

    // Sanity check of test setup - the 2 https servers should be cross-site
    // (the second server should have a different hostname because of the call
    // to SetSSLConfig with CERT_COMMON_NAME_IS_DOMAIN argument).
    ASSERT_FALSE(net::registry_controlled_domains::SameDomainOrHost(
        GetURLOnServiceWorkerServer("/"), GetURLOnCrossOriginServer("/"),
        net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES));
  }

  GURL GetURLOnServiceWorkerServer(const std::string& path) {
    return service_worker_https_server_.GetURL(path);
  }

  GURL GetURLOnCrossOriginServer(const std::string& path) {
    return cross_origin_https_server_.GetURL(path);
  }

  void StopCrossOriginServer() {
    EXPECT_TRUE(cross_origin_https_server_.ShutdownAndWaitUntilComplete());
  }

  void SetUpServiceWorker() {
    GURL url = GetURLOnServiceWorkerServer(
        "/cross_site_document_blocking/request.html");
    ASSERT_TRUE(NavigateToURL(shell(), url));

    // Register the service worker.
    bool is_script_done;
    std::string script = R"(
        navigator.serviceWorker
            .register('/cross_site_document_blocking/service_worker.js')
            .then(registration => navigator.serviceWorker.ready)
            .then(function(r) { domAutomationController.send(true); })
            .catch(function(e) {
                console.log('error: ' + e);
                domAutomationController.send(false);
            }); )";
    ASSERT_TRUE(ExecuteScriptAndExtractBool(shell(), script, &is_script_done));
    ASSERT_TRUE(is_script_done);

    // Navigate again to the same URL - the service worker should be 1) active
    // at this time (because of waiting for |navigator.serviceWorker.ready|
    // above) and 2) controlling the current page (because of the reload).
    ASSERT_TRUE(NavigateToURL(shell(), url));
    bool is_controlled_by_service_worker;
    ASSERT_TRUE(ExecuteScriptAndExtractBool(
        shell(),
        "domAutomationController.send(!!navigator.serviceWorker.controller)",
        &is_controlled_by_service_worker));
    ASSERT_TRUE(is_controlled_by_service_worker);
  }

 private:
  // The test requires 2 https servers, because:
  // 1. Service workers are only supported on secure origins.
  // 2. One of tests requires fetching cross-origin resources from the
  //    original page and/or service worker - the target of the fetch needs to
  //    be a https server to avoid hitting the mixed content error.
  net::EmbeddedTestServer service_worker_https_server_;
  net::EmbeddedTestServer cross_origin_https_server_;

  DISALLOW_COPY_AND_ASSIGN(CrossSiteDocumentBlockingServiceWorkerTest);
};

IN_PROC_BROWSER_TEST_F(CrossSiteDocumentBlockingServiceWorkerTest,
                       NetworkToServiceWorkerResponse) {
  SetUpServiceWorker();

  // Make sure that the histograms generated by a service worker registration
  // have been recorded.
  FetchHistogramsFromChildProcesses();

  // Build a script for XHR-ing a cross-origin, nosniff HTML document.
  GURL cross_origin_url =
      GetURLOnCrossOriginServer("/site_isolation/nosniff.txt");
  const char* script_template = R"(
      fetch('%s', { mode: 'no-cors' })
          .then(response => response.text())
          .then(responseText => {
              domAutomationController.send(responseText);
          })
          .catch(error => {
              var errorMessage = 'error: ' + error;
              domAutomationController.send(errorMessage);
          }); )";
  std::string script =
      base::StringPrintf(script_template, cross_origin_url.spec().c_str());

  // Make sure that base::HistogramTester below starts with a clean slate.
  FetchHistogramsFromChildProcesses();

  // The service worker will forward the request to the network, but a response
  // will be intercepted by the service worker and replaced with a new,
  // artificial error.
  base::HistogramTester histograms;
  std::string response;
  EXPECT_TRUE(ExecuteScriptAndExtractString(shell(), script, &response));

  // Verify that CORB blocked the response from the network (from
  // |cross_origin_https_server_|) to the service worker.
  InspectHistograms(histograms, kShouldBeBlockedWithoutSniffing, "network.txt",
                    blink::mojom::ResourceType::kXhr);

  // Verify that the service worker replied with an expected error.
  // Replying with an error means that CORB is only active once (for the
  // initial, real network request) and therefore the test doesn't get
  // confused (second successful response would have added noise to the
  // histograms captured by the test).
  EXPECT_EQ("error: TypeError: Failed to fetch", response);
}

// Test class to verify that --disable-web-security turns off CORB.
class CrossSiteDocumentBlockingDisableWebSecurityTest
    : public CrossSiteDocumentBlockingTestBase {
 public:
  CrossSiteDocumentBlockingDisableWebSecurityTest() {}
  ~CrossSiteDocumentBlockingDisableWebSecurityTest() override {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitch(switches::kDisableWebSecurity);
    CrossSiteDocumentBlockingTestBase::SetUpCommandLine(command_line);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CrossSiteDocumentBlockingDisableWebSecurityTest);
};

IN_PROC_BROWSER_TEST_F(CrossSiteDocumentBlockingDisableWebSecurityTest,
                       DisableBlocking) {
  // Load a page that issues illegal cross-site document requests.
  embedded_test_server()->StartAcceptingConnections();
  GURL foo_url("http://foo.com/cross_site_document_blocking/request.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  bool was_blocked;
  ASSERT_TRUE(ExecuteScriptAndExtractBool(
      shell(), "sendRequest(\"valid.html\");", &was_blocked));
  EXPECT_FALSE(was_blocked);
}

// Test class to verify that documents are blocked for isolated origins as well.
class CrossSiteDocumentBlockingIsolatedOriginTest
    : public CrossSiteDocumentBlockingTestBase {
 public:
  CrossSiteDocumentBlockingIsolatedOriginTest() {}
  ~CrossSiteDocumentBlockingIsolatedOriginTest() override {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitchASCII(switches::kIsolateOrigins,
                                    "http://bar.com");
    CrossSiteDocumentBlockingTestBase::SetUpCommandLine(command_line);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(CrossSiteDocumentBlockingIsolatedOriginTest);
};

IN_PROC_BROWSER_TEST_F(CrossSiteDocumentBlockingIsolatedOriginTest,
                       BlockDocumentsFromIsolatedOrigin) {
  embedded_test_server()->StartAcceptingConnections();

  if (AreAllSitesIsolatedForTesting())
    return;

  // Load a page that issues illegal cross-site document requests to the
  // isolated origin.
  GURL foo_url("http://foo.com/cross_site_document_blocking/request.html");
  EXPECT_TRUE(NavigateToURL(shell(), foo_url));

  bool was_blocked;
  ASSERT_TRUE(ExecuteScriptAndExtractBool(
      shell(), "sendRequest(\"valid.html\");", &was_blocked));
  EXPECT_TRUE(was_blocked);
}

}  // namespace content
