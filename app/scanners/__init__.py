import importlib
import importlib.util
import logging
import pkgutil
from app.config import settings
from app.scanners.base import BaseScanner

_registry: dict[str, BaseScanner] = {}
logger = logging.getLogger(__name__)
_OPTIONAL_SCANNER_DEPS = {
    "alibaba": "alibabacloud_tea_openapi",
    "aws": "boto3",
    "azure": "azure",
    "gcp": "google.cloud.aiplatform",
    "ibm": "ibm_watson",
}


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except ModuleNotFoundError:
        return False


def _scanner_enabled(name: str) -> bool:
    if name.startswith("k8s_"):
        return settings.scanner_k8s_enabled
    if not bool(getattr(settings, f"scanner_{name}_enabled", True)):
        return False
    dependency = _OPTIONAL_SCANNER_DEPS.get(name)
    return dependency is None or _module_available(dependency)


def _discover():
    import app.scanners as pkg
    for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
        if mod_name in ("base", "__init__"):
            continue
        if not _scanner_enabled(mod_name):
            logger.info("Scanner %s disabled by configuration", mod_name)
            continue
        try:
            mod = importlib.import_module(f"app.scanners.{mod_name}")
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BaseScanner) and obj is not BaseScanner:
                    instance = obj()
                    _registry[instance.name] = instance
        except Exception as e:
            logger.warning(f"Could not load scanner {mod_name}: {e}")


_discover()


def get_scanner(name: str) -> BaseScanner | None:
    return _registry.get(name)


def list_scanners() -> list[dict]:
    return [{"name": s.name, "display_name": s.display_name, "version": s.version} for s in _registry.values()]
