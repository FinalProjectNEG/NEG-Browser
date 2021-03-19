#!/usr/bin/env bash

# Copyright 2020 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

TMP=$(mktemp /tmp/audio.XXXXXX)
MP3_FILE="$TMP.mp3"
OUTPUT_FILE="/tmp/fake_audio.pcm"

main() {
    local arguments=${@}
    local arg_count=$#
    if [ $arg_count = 0 ]; then
        print_help
        exit 1
    elif [[ "$1" == "-"* ]]; then
        # We come here if the argument starts with a '-' like '-h'.
        print_help
        exit 2
    else
        send_audio "$arguments"
    fi
}

print_help() {
    cat <<END_OF_HELP

Usage: send-audio.sh the query

Example: send-audio.sh tell me a joke

This will send the given query to the fake Assistant microphone.
This allows sending voice queries even when you cannot access a real
microphone.
This only works
    - When running on Linux
    - When compiled with gn flag 'enable_fake_assistant_microphone'
    - after executing: sudo apt install httpie
END_OF_HELP

}

send_audio() {
    local text=$(echo $@ | tr " " "+")
    echo "Input text is: $text"

    echo "Performing text-to-speech"
    http --download "https://www.google.com/speech-api/v1/synthesize?lang=en&text=$text" --output $MP3_FILE --body
    echo "Converting to $OUTPUT_FILE"
    avconv -y -i $MP3_FILE -acodec pcm_s16le -f s16le -ar 16000 $OUTPUT_FILE \
         -loglevel error -hide_banner

    rm $MP3_FILE
}


main "$@"
