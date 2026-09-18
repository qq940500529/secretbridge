# SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
# SPDX-License-Identifier: AGPL-3.0-or-later
mode=$1
value=$2
if [ "$mode" = sleep ]; then sleep 15; exit 0; fi
if [ "$mode" = stdin ]; then value=$(cat); fi
if [ "$mode" = environment ]; then value=$SB_TEST_SECRET; fi
if [ "$mode" = file ]; then value=$(cat "$value"); fi
# Byte-by-byte writes exercise streaming filters even if the pipe coalesces reads.
remaining=$value
while [ -n "$remaining" ]; do
    rest=${remaining#?}
    first=${remaining%"$rest"}
    printf '%s' "$first"
    remaining=$rest
done
printf '|stdout-marker|\n'
printf '%s|stderr-marker|\n' "$value" >&2
if [ -n "$3" ]; then printf '|parameter:%s|\n' "$3"; fi
