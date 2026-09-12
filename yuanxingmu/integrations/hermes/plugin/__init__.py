"""Official Hermes plugin entry, loading only the host's read-only core copy."""
import os
from pathlib import Path
import sys


def register(ctx):
    root = Path(os.environ.get("YUANXINGMU_CORE_ROOT", ""))
    if not root.is_absolute() or not (root / "yuanxingmu" / "hermes_backend.py").is_file():
        raise RuntimeError("yuanxingmu_trusted_core_missing")
    root = root.resolve(strict=True)
    for name, module in tuple(sys.modules.items()):
        if name == "yuanxingmu" or name.startswith("yuanxingmu."):
            location = getattr(module, "__file__", None)
            if location is None or not Path(location).resolve().is_relative_to(root / "yuanxingmu"):
                raise RuntimeError("yuanxingmu_untrusted_core_already_loaded")
    sys.path.insert(0, str(root))
    from yuanxingmu.hermes_backend import register as register_backend
    return register_backend(ctx)
