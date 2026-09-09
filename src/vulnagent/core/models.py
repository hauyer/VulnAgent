"""Deprecated compatibility re-exports.

New code must import public models from :mod:`vulnagent.contracts`.
"""

from vulnagent.contracts import *  # noqa: F401,F403
from vulnagent.contracts.common import utc_now
