// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import {Destination, DestinationConnectionStatus, DestinationOrigin, DestinationStore, DestinationType, InvitationStore, LocalDestinationInfo, makeRecentDestination, NativeLayerImpl, RecentDestination} from 'chrome://print/print_preview.js';
import {assert} from 'chrome://resources/js/assert.m.js';
import {isChromeOS} from 'chrome://resources/js/cr.m.js';
import {loadTimeData} from 'chrome://resources/js/load_time_data.m.js';
import {keyEventOn} from 'chrome://resources/polymer/v3_0/iron-test-helpers/mock-interactions.js';
import {flush} from 'chrome://resources/polymer/v3_0/polymer/polymer_bundled.min.js';

import {assertEquals, assertFalse, assertTrue} from '../chai_assert.js';
import {eventToPromise} from '../test_util.m.js';

import {CloudPrintInterfaceStub} from './cloud_print_interface_stub.js';
import {NativeLayerStub} from './native_layer_stub.js';
import {createDestinationStore, getDestinations, getGoogleDriveDestination, setupTestListenerElement} from './print_preview_test_utils.js';

window.destination_dialog_test = {};
const destination_dialog_test = window.destination_dialog_test;
destination_dialog_test.suiteName = 'DestinationDialogTest';
/** @enum {string} */
destination_dialog_test.TestNames = {
  PrinterList: 'PrinterList',
  ShowProvisionalDialog: 'ShowProvisionalDialog',
  UserAccounts: 'UserAccounts',
  CloudPrinterDeprecationWarnings: 'CloudPrinterDeprecationWarnings',
  CloudPrinterDeprecationWarningsSuppressed:
      'CloudPrinterDeprecationWarningsSuppressed',
  SaveToDriveDeprecationWarnings: 'SaveToDriveDeprecationWarnings',
  SaveToDriveDeprecationWarningsSuppressed:
      'SaveToDriveDeprecationWarningsSuppressed',
  SaveToDriveDeprecationWarningsCros: 'SaveToDriveDeprecationWarningsCros',
  SaveToDriveDeprecationWarningsSuppressedCros:
      'SaveToDriveDeprecationWarningsSuppressedCros',
};

suite(destination_dialog_test.suiteName, function() {
  /** @type {!PrintPreviewDestinationDialogElement} */
  let dialog;

  /** @type {!DestinationStore} */
  let destinationStore;

  /** @type {!NativeLayerStub} */
  let nativeLayer;

  /** @type {!CloudPrintInterfaceStub} */
  let cloudPrintInterface;

  /** @type {!Array<!Destination>} */
  let destinations = [];

  /** @type {!Array<!LocalDestinationInfo>} */
  const localDestinations = [];

  /** @type {!Array<!RecentDestination>} */
  let recentDestinations = [];

  /** @type {boolean} */
  const saveToDriveFlagEnabled =
      isChromeOS && loadTimeData.getBoolean('printSaveToDrive');

  /** @override */
  suiteSetup(function() {
    setupTestListenerElement();
  });

  /** @override */
  setup(function() {
    // Create data classes
    nativeLayer = new NativeLayerStub();
    NativeLayerImpl.instance_ = nativeLayer;
    cloudPrintInterface = new CloudPrintInterfaceStub();
    destinationStore = createDestinationStore();
    destinationStore.setCloudPrintInterface(cloudPrintInterface);
    destinations = getDestinations(localDestinations);
    recentDestinations = [makeRecentDestination(destinations[4])];
    nativeLayer.setLocalDestinations(localDestinations);
    destinationStore.init(
        false /* pdfPrinterDisabled */, true /* isDriveMounted */,
        'FooDevice' /* printerName */,
        '' /* serializedDefaultDestinationSelectionRulesStr */,
        recentDestinations /* recentDestinations */);

    // Set up dialog
    dialog = /** @type {!PrintPreviewDestinationDialogElement} */ (
        document.createElement('print-preview-destination-dialog'));
    dialog.activeUser = '';
    dialog.users = [];
    dialog.destinationStore = destinationStore;
    dialog.invitationStore = new InvitationStore();
  });

  function finishSetup() {
    document.body.appendChild(dialog);
    return nativeLayer.whenCalled('getPrinterCapabilities')
        .then(function() {
          destinationStore.startLoadAllDestinations();
          dialog.show();
          return nativeLayer.whenCalled('getPrinters');
        })
        .then(function() {
          flush();
        });
  }

  // Test that destinations are correctly displayed in the lists.
  test(assert(destination_dialog_test.TestNames.PrinterList), async () => {
    await finishSetup();
    const list = dialog.$$('print-preview-destination-list');

    const printerItems =
        list.shadowRoot.querySelectorAll('print-preview-destination-list-item');

    const getDisplayedName = item => item.$$('.name').textContent;
    // 5 printers + Save as PDF
    assertEquals(6, printerItems.length);
    // Save as PDF shows up first.
    assertEquals(
        Destination.GooglePromotedId.SAVE_AS_PDF,
        getDisplayedName(printerItems[0]));
    assertEquals(
        'rgb(32, 33, 36)',
        window.getComputedStyle(printerItems[0].$$('.name')).color);
    // FooName will be second since it was updated by capabilities fetch.
    assertEquals('FooName', getDisplayedName(printerItems[1]));
    Array.from(printerItems).slice(2).forEach((item, index) => {
      assertEquals(destinations[index].displayName, getDisplayedName(item));
    });
  });

  // Test that clicking a provisional destination shows the provisional
  // destinations dialog, and that the escape key closes only the provisional
  // dialog when it is open, not the destinations dialog.
  test(
      assert(destination_dialog_test.TestNames.ShowProvisionalDialog),
      async () => {
        let provisionalDialog = null;
        const provisionalDestination = {
          extensionId: 'ABC123',
          extensionName: 'ABC Printing',
          id: 'XYZDevice',
          name: 'XYZ',
          provisional: true,
        };

        // Set the extension destinations and force the destination store to
        // reload printers.
        nativeLayer.setExtensionDestinations([provisionalDestination]);
        await finishSetup();
        flush();
        provisionalDialog =
            dialog.$$('print-preview-provisional-destination-resolver');
        assertFalse(provisionalDialog.$$('#dialog').open);
        const list = dialog.$$('print-preview-destination-list');
        const printerItems = list.shadowRoot.querySelectorAll(
            'print-preview-destination-list-item');

        // Should have 5 local destinations, Save as PDF + extension
        // destination.
        assertEquals(7, printerItems.length);
        const provisionalItem = Array.from(printerItems).find(printerItem => {
          return printerItem.destination.id === provisionalDestination.id;
        });

        // Click the provisional destination to select it.
        provisionalItem.click();
        flush();
        assertTrue(provisionalDialog.$$('#dialog').open);

        // Send escape key on provisionalDialog. Destinations dialog should
        // not close.
        const whenClosed = eventToPromise('close', provisionalDialog);
        keyEventOn(provisionalDialog, 'keydown', 19, [], 'Escape');
        flush();
        await whenClosed;

        assertFalse(provisionalDialog.$$('#dialog').open);
        assertTrue(dialog.$$('#dialog').open);
      });

  /**
   * @param {string} account The current active user account.
   * @param {number} numUsers The total number of users that are signed in.
   */
  function assertSignedInState(account, numUsers) {
    const signedIn = account !== '';
    assertEquals(!signedIn, dialog.$$('.user-info').hidden);

    if (numUsers > 0) {
      const userSelect = dialog.$$('.md-select');
      const userSelectOptions = userSelect.querySelectorAll('option');
      assertEquals(numUsers + 1, userSelectOptions.length);
      assertEquals('', userSelectOptions[numUsers].value);
      assertEquals(account, userSelect.value);
    }
  }

  /**
   * @param {number} numPrinters The total number of available printers.
   * @param {string} account The current active user account.
   */
  function assertNumPrintersWithDriveAccount(numPrinters, account) {
    const list = dialog.$$('print-preview-destination-list');
    const printerItems = list.shadowRoot.querySelectorAll(
        'print-preview-destination-list-item:not([hidden])');
    assertEquals(numPrinters, printerItems.length);

    if (isChromeOS && saveToDriveFlagEnabled) {
      return;
    }

    const drivePrinter = Array.from(printerItems).find(item => {
      return item.destination.id === Destination.GooglePromotedId.DOCS;
    });
    assertEquals(!!drivePrinter, account !== '');
    if (drivePrinter) {
      assertEquals(account, drivePrinter.destination.account);
    }
  }

  // Test that signing in and switching accounts works as expected.
  test(assert(destination_dialog_test.TestNames.UserAccounts), async () => {
    // Set up the cloud print interface with Google Drive printer for a couple
    // different accounts.
    const user1 = 'foo@chromium.org';
    const user2 = 'bar@chromium.org';
    cloudPrintInterface.setPrinter(getGoogleDriveDestination(user1));
    cloudPrintInterface.setPrinter(getGoogleDriveDestination(user2));
    let userSelect = null;

    await finishSetup();
    // Check that the user dropdown is hidden when there are no active users.
    assertTrue(dialog.$$('.user-info').hidden);
    userSelect = dialog.$$('.md-select');

    // Enable cloud print.
    assertSignedInState('', 0);
    // Local, extension, privet, and cloud (since
    // startLoadAllDestinations() was called).
    assertEquals(3, nativeLayer.getCallCount('getPrinters'));
    assertEquals(1, cloudPrintInterface.getCallCount('search'));

    // 6 printers, no Google drive (since not signed in).
    assertNumPrintersWithDriveAccount(6, '');

    // Set an active user.
    destinationStore.setActiveUser(user1);
    destinationStore.reloadUserCookieBasedDestinations(user1);
    dialog.activeUser = user1;
    dialog.users = [user1];
    flush();

    // Select shows the signed in user.
    assertSignedInState(user1, 1);

    // Now have 7 printers (Google Drive), with user1 signed in.
    // On CrOS we do not show Save to Drive destination so 6 printers expected.
    const expectedPrinters = isChromeOS && saveToDriveFlagEnabled ? 6 : 7;
    assertNumPrintersWithDriveAccount(expectedPrinters, user1);
    assertEquals(3, nativeLayer.getCallCount('getPrinters'));
    // Cloud printers should have been re-fetched.
    assertEquals(2, cloudPrintInterface.getCallCount('search'));

    // Simulate signing into a second account.
    userSelect.value = '';
    userSelect.dispatchEvent(new CustomEvent('change'));

    await nativeLayer.whenCalled('signIn');
    // No new printer fetch until the user actually changes the active
    // account.
    assertEquals(3, nativeLayer.getCallCount('getPrinters'));
    assertEquals(2, cloudPrintInterface.getCallCount('search'));
    dialog.users = [user1, user2];
    flush();

    // Select shows the signed in user.
    assertSignedInState(user1, 2);

    // Still have 7 printers (Google Drive), with user1 signed in.
    assertNumPrintersWithDriveAccount(expectedPrinters, user1);

    // Select the second account.
    const whenEventFired = eventToPromise('account-change', dialog);
    userSelect.value = user2;
    userSelect.dispatchEvent(new CustomEvent('change'));

    await whenEventFired;
    flush();

    // This will all be done by app.js and user_manager.js in response
    // to the account-change event.
    destinationStore.setActiveUser(user2);
    dialog.activeUser = user2;
    const whenInserted = eventToPromise(
        DestinationStore.EventType.DESTINATIONS_INSERTED, destinationStore);
    destinationStore.reloadUserCookieBasedDestinations(user2);

    await whenInserted;
    flush();

    assertSignedInState(user2, 2);

    // 7 printers (Google Drive), with user2 signed in.
    assertNumPrintersWithDriveAccount(expectedPrinters, user2);
    assertEquals(3, nativeLayer.getCallCount('getPrinters'));
    // Cloud print should have been queried again for the new account.
    assertEquals(3, cloudPrintInterface.getCallCount('search'));
  });

  /**
   * @param {boolean} warningsSuppressed Whether warnings are suppressed.
   * @return{!function()} Async function that tests whether Cloud print
   *     deprecation warnings show when they're supposed to.
   */
  function testCloudPrinterDeprecationWarnings(warningsSuppressed) {
    return async () => {
      loadTimeData.overrideValues(
          {cloudPrintDeprecationWarningsSuppressed: warningsSuppressed});

      // Set up the cloud print interface with a Cloud printer for an account.
      const user = 'foo@chromium.org';
      cloudPrintInterface.setPrinter(
          new Destination(
              'ID', DestinationType.GOOGLE, DestinationOrigin.COOKIES,
              'Cloud Printer', DestinationConnectionStatus.ONLINE,
              {account: user, isOwned: true}),
      );

      await finishSetup();

      // Nobody is signed in. There are no cloud printers.
      assertSignedInState('', 0);
      const statusEl = dialog.$$('.destinations-status');
      assertTrue(statusEl.hidden);

      // Set an active user. There is a cloud printer.
      destinationStore.setActiveUser(user);
      destinationStore.reloadUserCookieBasedDestinations(user);
      dialog.activeUser = user;
      dialog.users = [user];
      flush();
      assertSignedInState(user, 1);

      assertEquals(warningsSuppressed, statusEl.hidden);
    };
  }

  // Test that Cloud print deprecation warnings appear.
  test(
      assert(destination_dialog_test.TestNames.CloudPrinterDeprecationWarnings),
      testCloudPrinterDeprecationWarnings(false));

  // Test that Cloud print deprecation warnings are suppressed.
  test(
      assert(destination_dialog_test.TestNames
                 .CloudPrinterDeprecationWarningsSuppressed),
      testCloudPrinterDeprecationWarnings(true));

  /**
   * @param {boolean} warningsSuppressed Whether warnings are suppressed.
   * @return{!function()} Async function that tests whether Cloud print
   *     deprecation warnings show when they're supposed to.
   */
  function testSaveToDriveDeprecationWarnings(warningsSuppressed, isChromeOS) {
    return async () => {
      loadTimeData.overrideValues(
          {cloudPrintDeprecationWarningsSuppressed: warningsSuppressed});

      // Set up the cloud print interface with Google Drive printer for an
      // account.
      const user = 'foo@chromium.org';
      cloudPrintInterface.setPrinter(getGoogleDriveDestination(user));

      await finishSetup();

      // Nobody is signed in. There are no cloud printers.
      assertSignedInState('', 0);
      const statusEl = dialog.$$('.destinations-status');
      assertTrue(statusEl.hidden);

      // Set an active user. There is a cloud printer (Save to Drive).
      destinationStore.setActiveUser(user);
      destinationStore.reloadUserCookieBasedDestinations(user);
      dialog.activeUser = user;
      dialog.users = [user];
      flush();
      assertSignedInState(user, 1);

      // Warning should never appear on ChromeOS.
      assertEquals(warningsSuppressed || isChromeOS, statusEl.hidden);
    };
  }

  // Test that Save to Drive deprecation warnings appear.
  test(
      assert(destination_dialog_test.TestNames.SaveToDriveDeprecationWarnings),
      testSaveToDriveDeprecationWarnings(false, false));

  // Test that Save to Drive deprecation warnings are suppressed.
  test(
      assert(destination_dialog_test.TestNames
                 .SaveToDriveDeprecationWarningsSuppressed),
      testSaveToDriveDeprecationWarnings(true, false));

  // Test that Save to Drive deprecation warnings never appear.
  test(
      assert(
          destination_dialog_test.TestNames.SaveToDriveDeprecationWarningsCros),
      testSaveToDriveDeprecationWarnings(false, true));

  // Test that Save to Drive deprecation warnings are suppressed.
  test(
      assert(destination_dialog_test.TestNames
                 .SaveToDriveDeprecationWarningsSuppressedCros),
      testSaveToDriveDeprecationWarnings(true, true));
});
