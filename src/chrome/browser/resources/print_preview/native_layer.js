// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {assert} from 'chrome://resources/js/assert.m.js';
import {addSingletonGetter, sendWithPromise} from 'chrome://resources/js/cr.m.js';

import {Cdd, Destination} from './data/destination.js';
import {PrinterType} from './data/destination_match.js';
// <if expr="chromeos">
import {DestinationPolicies} from './data/destination_policies.js';
// </if>
import {MeasurementSystemUnitType} from './data/measurement_system.js';
// <if expr="chromeos">
import {PrinterStatus, PrinterStatusReason} from './data/printer_status_cros.js';
// </if>

/**
 * @typedef {{selectSaveAsPdfDestination: boolean,
 *            layoutSettings.portrait: boolean,
 *            pageRange: string,
 *            headersAndFooters: boolean,
 *            backgroundColorsAndImages: boolean,
 *            margins: number}}
 * @see chrome/browser/printing/print_preview_pdf_generated_browsertest.cc
 */
export let PreviewSettings;

/**
 * @typedef {{
 *   deviceName: string,
 *   printerName: string,
 *   printerDescription: (string | undefined),
 *   cupsEnterprisePrinter: (boolean | undefined),
 *   printerOptions: (Object | undefined),
 *   policies: (DestinationPolicies | undefined),
 * }}
 */
export let LocalDestinationInfo;

/**
 * Enumeration of background graphics printing mode restrictions used by
 * Chromium.
 * This has to coincide with |printing::BackgroundGraphicsModeRestriction| as
 * defined in printing/backend/printing_restrictions.h
 * @enum {number}
 */
export const BackgroundGraphicsModeRestriction = {
  UNSET: 0,
  ENABLED: 1,
  DISABLED: 2,
};

/**
 * Policies affecting print settings values and availability.
 * @typedef {{
 *   headerFooter: ({
 *     allowedMode: (boolean | undefined),
 *     defaultMode: (boolean | undefined),
 *   } | undefined),
 *   cssBackground: ({
 *     allowedMode: (BackgroundGraphicsModeRestriction | undefined),
 *     defaultMode: (BackgroundGraphicsModeRestriction | undefined),
 *   } | undefined),
 *   mediaSize: ({
 *     defaultMode: ({
 *       width: (number | undefined),
 *       height: (number | undefined),
 *     } | undefined),
 *   } | undefined),
 *   sheets: ({
 *     value: (number | undefined),
 *   } | undefined)
 * }}
 */
export let Policies;

/**
 * @typedef {{
 *   isInKioskAutoPrintMode: boolean,
 *   isInAppKioskMode: boolean,
 *   uiLocale: string,
 *   thousandsDelimiter: string,
 *   decimalDelimiter: string,
 *   unitType: !MeasurementSystemUnitType,
 *   previewModifiable: boolean,
 *   previewIsFromArc: boolean,
 *   previewIsPdf: boolean,
 *   documentTitle: string,
 *   documentHasSelection: boolean,
 *   shouldPrintSelectionOnly: boolean,
 *   printerName: string,
 *   policies: (Policies | undefined),
 *   serializedAppStateStr: ?string,
 *   serializedDefaultDestinationSelectionRulesStr: ?string,
 *   pdfPrinterDisabled: boolean,
 *   destinationsManaged: boolean,
 *   cloudPrintURL: (string | undefined),
 *   userAccounts: (Array<string> | undefined),
 *   syncAvailable: boolean,
 *   isDriveMounted: (boolean | undefined),
 * }}
 * @see corresponding field name definitions in print_preview_handler.cc
 */
export let NativeInitialSettings;

/**
 * @typedef {{
 *   serviceName: string,
 *   name: string,
 *   hasLocalPrinting: boolean,
 *   isUnregistered: boolean,
 *   cloudID: string,
 * }}
 * @see PrintPreviewHandler::FillPrinterDescription in
 * print_preview_handler.cc
 */
export let PrivetPrinterDescription;

/**
 * @typedef {{
 *   printer:(PrivetPrinterDescription |
 *            LocalDestinationInfo |
 *            undefined),
 *   capabilities: ?Cdd,
 * }}
 */
export let CapabilitiesResponse;

/**
 * @typedef {{
 *   printerId: string,
 *   success: boolean,
 *   capabilities: !Cdd,
 *   policies: (DestinationPolicies | undefined),
 * }}
 */
export let PrinterSetupResponse;

/**
 * @typedef {{
 *   extensionId: string,
 *   extensionName: string,
 *   id: string,
 *   name: string,
 *   description: (string|undefined),
 * }}
 */
export let ProvisionalDestinationInfo;

/**
 * An interface to the native Chromium printing system layer.
 * @interface
 */
export class NativeLayer {
  // <if expr="chromeos">
  /**
   * Requests access token for cloud print requests for DEVICE origin.
   * @return {!Promise<string>}
   */
  getAccessToken() {}
  // </if>

  /**
   * Gets the initial settings to initialize the print preview with.
   * @return {!Promise<!NativeInitialSettings>}
   */
  getInitialSettings() {}

  /**
   * Requests the system's print destinations. The promise will be resolved
   * when all destinations of that type have been retrieved. One or more
   * 'printers-added' events may be fired in response before resolution.
   * @param {!PrinterType} type The type of destinations to
   *     request.
   * @return {!Promise}
   */
  getPrinters(type) {}

  /**
   * Requests the destination's printing capabilities. Returns a promise that
   * will be resolved with the capabilities if they are obtained successfully.
   * @param {string} destinationId ID of the destination.
   * @param {!PrinterType} type The destination's printer type.
   * @return {!Promise<!CapabilitiesResponse>}
   */
  getPrinterCapabilities(destinationId, type) {}

  // <if expr="chromeos">
  /**
   * Requests the destination's end user license information. Returns a promise
   * that will be resolved with the destination's EULA URL if obtained
   * successfully.
   * @param {!string} destinationId ID of the destination.
   * @return {!Promise<string>}
   */
  getEulaUrl(destinationId) {}

  /**
   * Requests Chrome to resolve provisional extension destination by granting
   * the provider extension access to the printer.
   * @param {string} provisionalDestinationId
   * @return {!Promise<!ProvisionalDestinationInfo>}
   */
  grantExtensionPrinterAccess(provisionalDestinationId) {}

  /**
   * Requests that Chrome perform printer setup for the given printer.
   * @param {string} printerId
   * @return {!Promise<!PrinterSetupResponse>}
   */
  setupPrinter(printerId) {}
  // </if>

  /**
   * Requests that a preview be generated. The following Web UI events may
   * be triggered in response:
   *   'print-preset-options',
   *   'page-count-ready',
   *   'page-layout-ready',
   *   'page-preview-ready'
   * @param {string} printTicket JSON print ticket for the request.
   * @return {!Promise<number>} Promise that resolves with the unique ID of
   *     the preview UI when the preview has been generated.
   */
  getPreview(printTicket) {}

  /**
   * Opens the chrome://settings printing page. For Chrome OS, open the
   * printing settings in the Settings App.
   */
  openSettingsPrintPage() {}

  /**
   * Requests that the document be printed.
   * @param {string} printTicket The serialized print ticket for the print
   *     job.
   * @return {!Promise} Promise that will resolve when the print request is
   *     finished or rejected.
   */
  print(printTicket) {}

  /** Requests that the current pending print request be cancelled. */
  cancelPendingPrintRequest() {}

  /**
   * Sends the app state to be saved in the sticky settings.
   * @param {string} appStateStr JSON string of the app state to persist.
   */
  saveAppState(appStateStr) {}

  // <if expr="not chromeos and not is_win">
  /** Shows the system's native printing dialog. */
  showSystemDialog() {}
  // </if>

  /**
   * Closes the print preview dialog.
   * If |isCancel| is true, also sends a message to Print Preview Handler in
   * order to update UMA statistics.
   * @param {boolean} isCancel whether this was called due to the user
   *     closing the dialog without printing.
   */
  dialogClose(isCancel) {}

  /** Hide the print preview dialog and allow the native layer to close it. */
  hidePreview() {}

  /**
   * Opens the Google Cloud Print sign-in tab. If the user signs in
   * successfully, the user-accounts-updated event will be sent in response.
   */
  signIn() {}

  // <if expr="chromeos">
  /**
   * Sends a request to the printer with id |printerId| for its current status.
   * @param {string} printerId
   * @return {!Promise<!PrinterStatus>}
   */
  requestPrinterStatusUpdate(printerId) {}

  /**
   * Records the histogram to capture the printer status of the current
   * destination and whether the user chose to print or cancel.
   * @param {?PrinterStatusReason} statusReason Current destination printer
   * status
   * @param {boolean} didUserAttemptPrint True if user printed, false if user
   * canceled.
   */
  recordPrinterStatusHistogram(statusReason, didUserAttemptPrint) {}
  // </if>

  /**
   * Notifies the metrics handler to record a histogram value.
   * @param {string} histogram The name of the histogram to record
   * @param {number} bucket The bucket to record
   * @param {number} maxBucket The maximum bucket value in the histogram.
   */
  recordInHistogram(histogram, bucket, maxBucket) {}
}

/** @implements {NativeLayer} */
export class NativeLayerImpl {
  // <if expr="chromeos">
  /** @override */
  getAccessToken() {
    return sendWithPromise('getAccessToken');
  }
  // </if>

  /** @override */
  getInitialSettings() {
    return sendWithPromise('getInitialSettings');
  }

  /** @override */
  getPrinters(type) {
    return sendWithPromise('getPrinters', type);
  }

  /** @override */
  getPrinterCapabilities(destinationId, type) {
    return sendWithPromise('getPrinterCapabilities', destinationId, type);
  }

  // <if expr="chromeos">
  /** @override */
  getEulaUrl(destinationId) {
    return sendWithPromise('getEulaUrl', destinationId);
  }

  /** @override */
  grantExtensionPrinterAccess(provisionalDestinationId) {
    return sendWithPromise(
        'grantExtensionPrinterAccess', provisionalDestinationId);
  }

  /** @override */
  setupPrinter(printerId) {
    return sendWithPromise('setupPrinter', printerId);
  }
  // </if>

  /** @override */
  getPreview(printTicket) {
    return sendWithPromise('getPreview', printTicket);
  }

  /** @override */
  openSettingsPrintPage() {
    chrome.send('openPrinterSettings');
  }

  /** @override */
  print(printTicket) {
    return sendWithPromise('print', printTicket);
  }

  /** @override */
  cancelPendingPrintRequest() {
    chrome.send('cancelPendingPrintRequest');
  }

  /** @override */
  saveAppState(appStateStr) {
    chrome.send('saveAppState', [appStateStr]);
  }

  // <if expr="not chromeos and not is_win">
  /** @override */
  showSystemDialog() {
    chrome.send('showSystemDialog');
  }
  // </if>

  /** @override */
  dialogClose(isCancel) {
    if (isCancel) {
      chrome.send('closePrintPreviewDialog');
    }
    chrome.send('dialogClose');
  }

  /** @override */
  hidePreview() {
    chrome.send('hidePreview');
  }

  /** @override */
  signIn() {
    chrome.send('signIn');
  }

  // <if expr="chromeos">
  /** @override */
  requestPrinterStatusUpdate(printerId) {
    return sendWithPromise('requestPrinterStatus', printerId);
  }

  /** @override */
  recordPrinterStatusHistogram(statusReason, didUserAttemptPrint) {
    if (!statusReason) {
      return;
    }

    let histogram;
    switch (statusReason) {
      case (PrinterStatusReason.NO_ERROR):
        histogram = 'PrintPreview.PrinterStatus.AttemptedPrintWithGoodStatus';
        break;
      case (PrinterStatusReason.UNKNOWN_REASON):
        histogram =
            'PrintPreview.PrinterStatus.AttemptedPrintWithUnknownStatus';
        break;
      default:
        histogram = 'PrintPreview.PrinterStatus.AttemptedPrintWithErrorStatus';
        break;
    }
    chrome.send(
        'metricsHandler:recordBooleanHistogram',
        [histogram, didUserAttemptPrint]);
  }
  // </if>

  /** @override */
  recordInHistogram(histogram, bucket, maxBucket) {
    chrome.send(
        'metricsHandler:recordInHistogram', [histogram, bucket, maxBucket]);
  }
}

addSingletonGetter(NativeLayerImpl);
