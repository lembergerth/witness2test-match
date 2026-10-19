#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "$0")"
exec ./integration-test.sh "$@"
