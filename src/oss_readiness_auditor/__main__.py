# SPDX-FileCopyrightText: 2026 DB InfraGO AG
# SPDX-License-Identifier: Apache-2.0
# oss-readiness-auditor: rule source
"""python -m oss_readiness_auditor"""

import sys

from .cli import main

sys.exit(main())
