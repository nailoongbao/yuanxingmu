"""Optional native SDK tools. Importing this package requires no SDK dependency.

These adapters are tool bindings, not process sandboxes. The trusted host binds
the Broker socket and session before handing tools to a framework.
"""

from .client import NativeTools

__all__ = ["NativeTools"]
