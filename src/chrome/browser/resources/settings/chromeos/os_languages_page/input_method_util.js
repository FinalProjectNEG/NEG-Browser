// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// #import {assert, assertNotReached} from 'chrome://resources/js/assert.m.js';

/**
 * @fileoverview constants related to input method options.
 */
cr.define('settings.input_method_util', function() {
  /**
   * The prefix string shared by all first party input method ID.
   * @private @const
   */
  /* #export */ const FIRST_PARTY_INPUT_METHOD_ID_PREFIX =
      '_comp_ime_jkghodnilhceideoidjikpgommlajknk';

  /**
   * All possible keyboard layouts.
   *
   * @enum {string}
   */
  const KeyboardLayout = {
    STANDARD: 'Default',
    GINYIEH: 'Gin Yieh',
    ETEN: 'Eten',
    IBM: 'IBM',
    HSU: 'Hsu',
    ETEN26: 'Eten 26',
    SET2: '2 Set / 두벌식',
    SET2Y: '2 Set (Old Hangul) / 두벌식 (옛글)',
    SET32: '3 Set (2 set) / 세벌식 (두벌)',
    SET390: '3 Set (390) / 세벌식 (390)',
    SET3_FINAL: '3 Set (Final) / 세벌식 (최종)',
    SET3_SUN: '3 Set (No Shift) / 세벌식 (순아래)',
    SET3_YET: '3 Set (Old Hangul) / 세벌식 (옛글)',
    ROMAJA: 'Romaja / 로마자',
    AHN: 'Ahnmatae / 안마태',
    XKB_US: 'US',
    XKB_DVORAK: 'Dvorak',
    XKB_COLEMAK: 'Colemak'
  };

  /**
   * All possible options on options pages.
   *
   * @enum {string}
   */
  /* #export */ const OptionType = {
    EDIT_USER_DICT: 'editUserDict',
    ENABLE_COMPLETION: 'enableCompletion',
    ENABLE_DOUBLE_SPACE_PERIOD: 'enableDoubleSpacePeriod',
    ENABLE_GESTURE_TYPING: 'enableGestureTyping',
    ENABLE_PREDICTION: 'enablePrediction',
    ENABLE_SOUND_ON_KEYPRESS: 'enableSoundOnKeypress',
    PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
        'physicalKeyboardAutoCorrectionLevel',
    PHYSICAL_KEYBOARD_ENABLE_CAPITALIZATION:
        'physicalKeyboardEnableCapitalization',
    VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
        'virtualKeyboardAutoCorrectionLevel',
    VIRTUAL_KEYBOARD_ENABLE_CAPITALIZATION:
        'virtualKeyboardEnableCapitalization',
    XKB_LAYOUT: 'xkbLayout',
    // Options for Korean input method.
    KOREAN_ENABLE_SYLLABLE_INPUT: 'koreanEnableSyllableInput',
    KOREAN_KEYBOARD_LAYOUT: 'koreanKeyboardLayout',
    KOREAN_SHOW_HANGUL_CANDIDATE: 'koreanShowHangulCandidate',
    // Options for pinyin input method.
    PINYIN_CHINESE_PUNCTUATION: 'pinyinChinesePunctuation',
    PINYIN_DEFAULT_CHINESE: 'pinyinDefaultChinese',
    PINYIN_ENABLE_FUZZY: 'pinyinEnableFuzzy',
    PINYIN_ENABLE_LOWER_PAGING: 'pinyinEnableLowerPaging',
    PINYIN_ENABLE_UPPER_PAGING: 'pinyinEnableUpperPaging',
    PINYIN_FULL_WIDTH_CHARACTER: 'pinyinFullWidthCharacter',
    PINYIN_FUZZY_CONFIG: 'pinyinFuzzyConfig',
    // Options for zhuyin input method.
    ZHUYIN_KEYBOARD_LAYOUT: 'zhuyinKeyboardLayout',
    ZHUYIN_PAGE_SIZE: 'zhuyinPageSize',
    ZHUYIN_SELECT_KEYS: 'zhuyinSelectKeys',
  };

  /**
   * Default values for each option type.
   *
   * @type {Object<settings.input_method_util.OptionType, *>}
   * @const
   */
  /* #export */ const OPTION_DEFAULT = {
    [OptionType.ENABLE_COMPLETION]: false,
    [OptionType.ENABLE_DOUBLE_SPACE_PERIOD]: false,
    [OptionType.ENABLE_GESTURE_TYPING]: true,
    [OptionType.ENABLE_PREDICTION]: false,
    [OptionType.ENABLE_SOUND_ON_KEYPRESS]: false,
    [OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL]: 0,
    [OptionType.PHYSICAL_KEYBOARD_ENABLE_CAPITALIZATION]: true,
    [OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL]: 1,
    [OptionType.VIRTUAL_KEYBOARD_ENABLE_CAPITALIZATION]: false,
    [OptionType.XKB_LAYOUT]: 'US',
    // Options for Korean input method.
    [OptionType.KOREAN_ENABLE_SYLLABLE_INPUT]: true,
    [OptionType.KOREAN_KEYBOARD_LAYOUT]: KeyboardLayout.SET2,
    [OptionType.KOREAN_SHOW_HANGUL_CANDIDATE]: false,
    // Options for pinyin input method.
    [OptionType.PINYIN_CHINESE_PUNCTUATION]: true,
    [OptionType.PINYIN_DEFAULT_CHINESE]: true,
    [OptionType.PINYIN_ENABLE_FUZZY]: false,
    [OptionType.PINYIN_ENABLE_LOWER_PAGING]: true,
    [OptionType.PINYIN_ENABLE_UPPER_PAGING]: true,
    [OptionType.PINYIN_FULL_WIDTH_CHARACTER]: false,
    [OptionType.PINYIN_FUZZY_CONFIG]: {
      an_ang: undefined,
      c_ch: undefined,
      en_eng: undefined,
      f_h: undefined,
      ian_iang: undefined,
      in_ing: undefined,
      k_g: undefined,
      l_n: undefined,
      r_l: undefined,
      s_sh: undefined,
      uan_uang: undefined,
      z_zh: undefined
    },
    // Options for zhuyin input method.
    [OptionType.ZHUYIN_KEYBOARD_LAYOUT]: KeyboardLayout.STANDARD,
    [OptionType.ZHUYIN_PAGE_SIZE]: 10,
    [OptionType.ZHUYIN_SELECT_KEYS]: '1234567890',
  };

  /**
   * All possible UI elements for options.
   *
   * @enum {string}
   */
  /* #export */ const UiType = {
    TOGGLE_BUTTON: 'toggleButton',
    DROPDOWN: 'dropdown',
    LINK: 'link',
  };

  /**
   * Enumeration for input tool codes.
   *
   * @enum {string}
   */
  /* #export */ const InputToolCode = {
    PINYIN_CHINESE_SIMPLIFIED: 'zh-t-i0-pinyin',
    ZHUYIN_CHINESE_TRADITIONAL: 'zh-hant-t-i0-und',
    XKB_US_ENG: 'xkb:us::eng',
  };

  /**
   * @param {string} id Input method ID.
   * @return {string} The corresponding engind ID of the input method.
   */
  /* #export */ function getFirstPartyInputMethodEngineId(id) {
    assert(isFirstPartyInputMethodId_(id));
    return id.substring(FIRST_PARTY_INPUT_METHOD_ID_PREFIX.length);
  }

  /**
   * @param {string} id Input method ID.
   * @return {boolean} true if the input method's options page is implemented.
   */
  /* #export */ function hasOptionsPageInSettings(id) {
    if (!isFirstPartyInputMethodId_(id)) {
      return false;
    }
    const engineId = getFirstPartyInputMethodEngineId(id);
    return engineId === InputToolCode.PINYIN_CHINESE_SIMPLIFIED ||
        engineId === InputToolCode.XKB_US_ENG;
  }

  /**
   * Generates options to be displayed in the options page, grouped by sections.
   * @param {string} engineId Input method engine ID.
   * @return {!Array<!{title: string, optionNames:
   *     !Array<settings.input_method_util.OptionType>}>} the options to be
   *     displayed.
   */
  /* #export */ function generateOptions(engineId) {
    const options =
        {basic: [], advanced: [], physicalKeyboard: [], virtualKeyboard: []};
    if (engineId === InputToolCode.PINYIN_CHINESE_SIMPLIFIED) {
      options.basic.push(
          OptionType.XKB_LAYOUT, OptionType.PINYIN_ENABLE_UPPER_PAGING,
          OptionType.PINYIN_ENABLE_LOWER_PAGING,
          OptionType.PINYIN_DEFAULT_CHINESE,
          OptionType.PINYIN_FULL_WIDTH_CHARACTER,
          OptionType.PINYIN_CHINESE_PUNCTUATION);
      options.advanced.push(
          OptionType.PINYIN_ENABLE_FUZZY, OptionType.EDIT_USER_DICT);
    }
    if (engineId === InputToolCode.XKB_US_ENG) {
      options.physicalKeyboard.push(
          OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL,
          OptionType.PHYSICAL_KEYBOARD_ENABLE_CAPITALIZATION,
          OptionType.ENABLE_PREDICTION);
      options.virtualKeyboard.push(
          OptionType.ENABLE_SOUND_ON_KEYPRESS,
          OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL,
          OptionType.VIRTUAL_KEYBOARD_ENABLE_CAPITALIZATION,
          OptionType.ENABLE_DOUBLE_SPACE_PERIOD,
          OptionType.ENABLE_GESTURE_TYPING, OptionType.EDIT_USER_DICT);
    }

    return [
      {
        title: 'basic',
        optionNames: options.basic,
      },
      {
        title: 'advanced',
        optionNames: options.advanced,
      },
      {
        title: 'physicalKeyboard',
        optionNames: options.physicalKeyboard,
      },
      {
        title: 'virtualKeyboard',
        optionNames: options.virtualKeyboard,
      },
    ];
  }

  /**
   * @param {!settings.input_method_util.OptionType} option The option type.
   * @return {settings.input_method_util.UiType} The UI type of |option|.
   */
  /* #export */ function getOptionUiType(option) {
    switch (option) {
      case OptionType.ENABLE_COMPLETION:
      case OptionType.ENABLE_DOUBLE_SPACE_PERIOD:
      case OptionType.ENABLE_GESTURE_TYPING:
      case OptionType.ENABLE_PREDICTION:
      case OptionType.ENABLE_SOUND_ON_KEYPRESS:
      case OptionType.PHYSICAL_KEYBOARD_ENABLE_CAPITALIZATION:
      case OptionType.VIRTUAL_KEYBOARD_ENABLE_CAPITALIZATION:
      case OptionType.KOREAN_ENABLE_SYLLABLE_INPUT:
      case OptionType.KOREAN_SHOW_HANGUL_CANDIDATE:
      case OptionType.PINYIN_CHINESE_PUNCTUATION:
      case OptionType.PINYIN_DEFAULT_CHINESE:
      case OptionType.PINYIN_ENABLE_FUZZY:
      case OptionType.PINYIN_ENABLE_LOWER_PAGING:
      case OptionType.PINYIN_ENABLE_UPPER_PAGING:
      case OptionType.PINYIN_FULL_WIDTH_CHARACTER:
        return UiType.TOGGLE_BUTTON;
      case OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
      case OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
      case OptionType.XKB_LAYOUT:
      case OptionType.KOREAN_KEYBOARD_LAYOUT:
      case OptionType.ZHUYIN_KEYBOARD_LAYOUT:
      case OptionType.ZHUYIN_SELECT_KEYS:
      case OptionType.ZHUYIN_PAGE_SIZE:
        return UiType.DROPDOWN;
      case OptionType.EDIT_USER_DICT:
        return UiType.LINK;
      default:
        assertNotReached();
    }
  }

  /**
   * @param {!settings.input_method_util.OptionType} option The option type.
   * @return {string} The name of the i18n string for the label of |option|.
   */
  /* #export */ function getOptionLabelName(option) {
    switch (option) {
      case OptionType.ENABLE_DOUBLE_SPACE_PERIOD:
        return 'inputMethodOptionsEnableDoubleSpacePeriod';
      case OptionType.ENABLE_GESTURE_TYPING:
        return 'inputMethodOptionsEnableGestureTyping';
      case OptionType.ENABLE_PREDICTION:
        return 'inputMethodOptionsEnablePrediction';
      case OptionType.ENABLE_SOUND_ON_KEYPRESS:
        return 'inputMethodOptionsEnableSoundOnKeypress';
      case OptionType.PHYSICAL_KEYBOARD_ENABLE_CAPITALIZATION:
      case OptionType.VIRTUAL_KEYBOARD_ENABLE_CAPITALIZATION:
        return 'inputMethodOptionsEnableCapitalization';
      case OptionType.PINYIN_CHINESE_PUNCTUATION:
        return 'inputMethodOptionsPinyinChinesePunctuation';
      case OptionType.PINYIN_DEFAULT_CHINESE:
        return 'inputMethodOptionsPinyinDefaultChinese';
      case OptionType.PINYIN_ENABLE_FUZZY:
        return 'inputMethodOptionsPinyinEnableFuzzy';
      case OptionType.PINYIN_ENABLE_LOWER_PAGING:
        return 'inputMethodOptionsPinyinEnableLowerPaging';
      case OptionType.PINYIN_ENABLE_UPPER_PAGING:
        return 'inputMethodOptionsPinyinEnableUpperPaging';
      case OptionType.PINYIN_FULL_WIDTH_CHARACTER:
        return 'inputMethodOptionsPinyinFullWidthCharacter';
      case OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
      case OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
        return 'inputMethodOptionsAutoCorrection';
      case OptionType.XKB_LAYOUT:
        return 'inputMethodOptionsXkbLayout';
      case OptionType.EDIT_USER_DICT:
        return 'inputMethodOptionsEditUserDict';
      default:
        assertNotReached();
    }
  }

  /**
   * @param {!settings.input_method_util.OptionType} option The option type.
   * @return {!Array<!{value: *, name: string}>} The list of items to be
   *     displayed in the dropdown for |option|.
   */
  /* #export */ function getOptionMenuItems(option) {
    switch (option) {
      case OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
      case OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL:
        return [
          {value: 0, name: 'inputMethodOptionsAutoCorrectionOff'},
          {value: 1, name: 'inputMethodOptionsAutoCorrectionModest'},
          {value: 2, name: 'inputMethodOptionsAutoCorrectionAggressive'}
        ];
      case OptionType.XKB_LAYOUT:
        return [
          {value: 'US', name: 'inputMethodOptionsUsKeyboard'},
          {value: 'Dvorak', name: 'inputMethodOptionsDvorakKeyboard'},
          {value: 'Colemak', name: 'inputMethodOptionsColemakKeyboard'}
        ];
      default:
        return [];
    }
  }

  /**
   * @param {!settings.input_method_util.OptionType} option The option type.
   * @return {boolean} true if the value for |option| is a number.
   */
  /* #export */ function isNumberValue(option) {
    return option === OptionType.PHYSICAL_KEYBOARD_AUTO_CORRECTION_LEVEL ||
        option === OptionType.VIRTUAL_KEYBOARD_AUTO_CORRECTION_LEVEL;
  }

  /**
   * @param {!settings.input_method_util.OptionType} option The option type.
   * @return {string|undefined} The url to open for |option|, returns undefined
   *     if |option| does not have a url.
   */
  /* #export */ function getOptionUrl(option) {
    if (option === OptionType.EDIT_USER_DICT) {
      return 'chrome://settings/editDictionary';
    }
    return undefined;
  }

  /**
   * @param {string} id Input method ID.
   * @return {boolean} true if |id| is a first party input method ID.
   * @private
   */
  function isFirstPartyInputMethodId_(id) {
    return id.startsWith(FIRST_PARTY_INPUT_METHOD_ID_PREFIX);
  }

  // #cr_define_end
  return {
    OptionType,
    OPTION_DEFAULT,
    UiType,
    InputToolCode,
    getFirstPartyInputMethodEngineId,
    hasOptionsPageInSettings,
    generateOptions,
    getOptionUiType,
    getOptionLabelName,
    getOptionMenuItems,
    getOptionUrl,
    isNumberValue,
  };
});
