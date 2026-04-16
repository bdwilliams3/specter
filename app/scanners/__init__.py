import importlib
import pkgutil
from app.scanners.base import BaseScanner

_registry: dict[str, BaseScanner] = {}


def _discover():
    import app.scanners as pkg
    for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
        if mod_name in ("base", "__init__"):
            continue
        try:
            mod = importlib.import_module(f"app.scanners.{mod_name}")
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, BaseScanner) and obj is not BaseScanner:
                    instance = obj()
                    _registry[instance.name] = instance
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Could not load scanner {mod_name}: {e}")


_discover()


def get_scanner(name: str) -> BaseScanner | None:
    return _registry.get(name)


def list_scanners() -> list[dict]:
    return [{"name": s.name, "display_name": s.display_name, "version": s.version} for s in _registry.values()]
