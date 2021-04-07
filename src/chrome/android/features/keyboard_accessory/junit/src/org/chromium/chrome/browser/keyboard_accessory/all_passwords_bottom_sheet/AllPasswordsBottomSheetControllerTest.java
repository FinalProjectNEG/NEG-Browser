// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.AllPasswordsBottomSheetActions.CREDENTIAL_SELECTED;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.AllPasswordsBottomSheetActions.SEARCH_USED;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.AllPasswordsBottomSheetActions.SHEET_DISMISSED;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.UMA_ALL_PASSWORDS_BOTTOM_SHEET_ACTIONS;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.UMA_WARNING_ACTIONS;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetProperties.CredentialProperties.CREDENTIAL;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetProperties.DISMISS_HANDLER;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetProperties.SHEET_ITEMS;
import static org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetProperties.VISIBLE;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.annotation.Config;

import org.chromium.base.metrics.test.ShadowRecordHistogram;
import org.chromium.base.test.BaseRobolectricTestRunner;
import org.chromium.base.test.util.JniMocker;
import org.chromium.chrome.browser.flags.ChromeFeatureList;
import org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetMetricsRecorder.AllPasswordsWarningActions;
import org.chromium.chrome.browser.keyboard_accessory.all_passwords_bottom_sheet.AllPasswordsBottomSheetProperties.ItemType;
import org.chromium.chrome.test.util.browser.Features;
import org.chromium.components.browser_ui.bottomsheet.BottomSheetController;
import org.chromium.components.embedder_support.util.UrlUtilities;
import org.chromium.components.embedder_support.util.UrlUtilitiesJni;
import org.chromium.ui.modaldialog.DialogDismissalCause;
import org.chromium.ui.modaldialog.ModalDialogManager;
import org.chromium.ui.modaldialog.ModalDialogProperties;
import org.chromium.ui.modaldialog.ModalDialogProperties.ButtonType;
import org.chromium.ui.modelutil.ListModel;
import org.chromium.ui.modelutil.MVCListAdapter.ListItem;
import org.chromium.ui.modelutil.PropertyModel;

/**
 * Controller tests for the all passwords bottom sheet.
 */
@RunWith(BaseRobolectricTestRunner.class)
@Config(manifest = Config.NONE, shadows = {ShadowRecordHistogram.class})
@Features.EnableFeatures(ChromeFeatureList.FILLING_PASSWORDS_FROM_ANY_ORIGIN)
public class AllPasswordsBottomSheetControllerTest {
    private static final Credential ANA =
            new Credential("Ana", "S3cr3t", "Ana", "https://m.domain.xyz/", false, "");
    private static final Credential BOB =
            new Credential("Bob", "*****", "Bob", "https://subdomain.example.xyz", false, "");
    private static final Credential CARL =
            new Credential("Carl", "G3h3!m", "Carl", "https://www.origin.xyz", false, "");
    private static final Credential[] TEST_CREDENTIALS = new Credential[] {BOB, CARL, ANA};
    private static final boolean IS_PASSWORD_FIELD = true;

    @Rule
    public JniMocker mJniMocker = new JniMocker();
    @Rule
    public TestRule mFeaturesProcessorRule = new Features.JUnitProcessor();
    @Mock
    private UrlUtilities.Natives mUrlUtilitiesJniMock;
    @Mock
    private AllPasswordsBottomSheetCoordinator.Delegate mMockDelegate;
    @Mock
    private ModalDialogManager mModalDialogManager;

    private AllPasswordsBottomSheetMediator mMediator;
    private PropertyModel mModel;
    private PropertyModel mModalDialogModel;

    @Before
    public void setUp() {
        ShadowRecordHistogram.reset();
        MockitoAnnotations.initMocks(this);
        mJniMocker.mock(UrlUtilitiesJni.TEST_HOOKS, mUrlUtilitiesJniMock);
        mMediator = new AllPasswordsBottomSheetMediator();
        mModalDialogModel = getModalDialogModel(mMediator);
        mModel = AllPasswordsBottomSheetProperties.createDefaultModel(
                mMediator::onDismissed, mMediator::onQueryTextChange);
        mMediator.initialize(mModalDialogManager, mModalDialogModel, mMockDelegate, mModel);

        when(mUrlUtilitiesJniMock.getDomainAndRegistry(anyString(), anyBoolean()))
                .then(inv -> getDomainAndRegistry(inv.getArgument(0)));
    }

    @Test
    public void testCreatesValidDefaultModel() {
        assertNotNull(mModel.get(SHEET_ITEMS));
        assertNotNull(mModel.get(DISMISS_HANDLER));
        assertThat(mModel.get(VISIBLE), is(false));
    }

    @Test
    public void testWarningModalDialog() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.warnAndShow();
        verify(mModalDialogManager)
                .showDialog(mModalDialogModel, ModalDialogManager.ModalDialogType.APP);
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_WARNING_ACTIONS, AllPasswordsWarningActions.WARNING_DIALOG_SHOWN),
                is(1));
    }

    @Test
    public void testBottomSheetIsShowingIfWarningAccepted() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        assertThat(mModel.get(VISIBLE), is(true));
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_WARNING_ACTIONS, AllPasswordsWarningActions.WARNING_ACCEPTED),
                is(1));
    }

    @Test
    public void testBottomSheetNotShowingIfWarningDismissed() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ButtonType.NEGATIVE);
        mMediator.onDismiss(mModalDialogModel, DialogDismissalCause.NEGATIVE_BUTTON_CLICKED);
        assertThat(mModel.get(VISIBLE), is(false));
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_WARNING_ACTIONS, AllPasswordsWarningActions.WARNING_CANCELED),
                is(1));
    }

    @Test
    public void testShowCredentialSetsCredentialListModel() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);

        ListModel<ListItem> itemList = mModel.get(SHEET_ITEMS);
        assertThat(itemList.size(), is(3));

        assertThat(itemList.get(0).type, is(ItemType.CREDENTIAL));
        assertThat(itemList.get(0).model.get(CREDENTIAL), is(ANA));
        assertThat(itemList.get(1).type, is(ItemType.CREDENTIAL));
        assertThat(itemList.get(1).model.get(CREDENTIAL), is(BOB));
        assertThat(itemList.get(2).type, is(ItemType.CREDENTIAL));
        assertThat(itemList.get(2).model.get(CREDENTIAL), is(CARL));
    }

    @Test
    public void testOnCredentialSelected() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        mMediator.onCredentialSelected(TEST_CREDENTIALS[1]);
        assertThat(mModel.get(VISIBLE), is(false));
        verify(mMockDelegate).onCredentialSelected(TEST_CREDENTIALS[1]);
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_ALL_PASSWORDS_BOTTOM_SHEET_ACTIONS, CREDENTIAL_SELECTED),
                is(1));
    }

    @Test
    public void testRecordingSearchMetrics() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        mMediator.onQueryTextChange("Bob");
        mMediator.onCredentialSelected(TEST_CREDENTIALS[1]);
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_ALL_PASSWORDS_BOTTOM_SHEET_ACTIONS, SEARCH_USED),
                is(1));
    }

    @Test
    public void testOnDismiss() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        mMediator.onDismissed(BottomSheetController.StateChangeReason.BACK_PRESS);
        assertThat(mModel.get(VISIBLE), is(false));
        verify(mMockDelegate).onDismissed();
        assertThat(ShadowRecordHistogram.getHistogramValueCountForTesting(
                           UMA_ALL_PASSWORDS_BOTTOM_SHEET_ACTIONS, SHEET_DISMISSED),
                is(1));
    }

    @Test
    public void testSearchFilterByUsername() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        mMediator.onQueryTextChange("Bob");
        assertThat(mModel.get(SHEET_ITEMS).size(), is(1));
    }

    @Test
    public void testSearchFilterByURL() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);
        mMediator.onClick(mModalDialogModel, ModalDialogProperties.ButtonType.POSITIVE);
        mMediator.onQueryTextChange("subdomain");
        assertThat(mModel.get(SHEET_ITEMS).size(), is(1));
    }

    @Test
    public void testCredentialSortedByOrigin() {
        mMediator.setCredentials(TEST_CREDENTIALS, IS_PASSWORD_FIELD);

        ListModel<ListItem> itemList = mModel.get(SHEET_ITEMS);

        assertThat(itemList.get(0).model.get(CREDENTIAL), is(ANA));
        assertThat(itemList.get(1).model.get(CREDENTIAL), is(BOB));
        assertThat(itemList.get(2).model.get(CREDENTIAL), is(CARL));
    }

    private PropertyModel getModalDialogModel(AllPasswordsBottomSheetMediator mediator) {
        return new PropertyModel.Builder(ModalDialogProperties.ALL_KEYS)
                .with(ModalDialogProperties.CONTROLLER, mediator)
                .with(ModalDialogProperties.FILTER_TOUCH_FOR_SECURITY, true)
                .build();
    }

    /**
     * Helper to get organization-identifying host from URLs. The real implementation calls
     * {@link UrlUtilities}. It's not useful to actually reimplement it, so just return a string in
     * a trivial way.
     * @param origin A URL.
     * @return The organization-identifying host from the given URL.
     */
    private String getDomainAndRegistry(String origin) {
        return origin.replaceAll(".*\\.(.+\\.[^.]+$)", "$1");
    }
}
