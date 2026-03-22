"""
core/module_loader.py
---------------------
Dynamic plugin loader. Maps CLI module names to their class implementations.
"""

import importlib
from typing import Optional, Type, List
from utils.logger import get_logger

MODULE_REGISTRY = {
    "sqli":     ("modules.sqli",     "SQLiModule"),
    "xss":      ("modules.xss",      "XSSModule"),
    "auth":     ("modules.auth",     "AuthModule"),
    "lfi":      ("modules.lfi",      "LFIModule"),
    "ssrf":     ("modules.ssrf",     "SSRFModule"),
    "redirect": ("modules.redirect", "OpenRedirectModule"),
    "idor":     ("modules.idor",     "IDORModule"),
    "cmdi":     ("modules.cmdi",     "CMDiModule"),
}


def load_module(module_name: str) -> Optional[Type]:
    """Dynamically load and return an exploit module class by name."""
    logger = get_logger()
    if module_name not in MODULE_REGISTRY:
        logger.error(
            f"Unknown module: '{module_name}'. "
            f"Available: {', '.join(MODULE_REGISTRY.keys())}"
        )
        return None
    module_path, class_name = MODULE_REGISTRY[module_name]
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError) as e:
        logger.error(f"Failed to load module '{module_name}': {e}")
        return None


def list_modules() -> List[str]:
    """Return all registered module names."""
    return list(MODULE_REGISTRY.keys())
