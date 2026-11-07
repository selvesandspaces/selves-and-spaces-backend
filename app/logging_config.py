import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_MAX_BYTES = 5 * 1024 * 1024
_BACKUPS = 5


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Messages like "order.paid via=webhook order=ab12" also get
    `event` ("order.paid") and `fields` ({"via": "webhook", "order": "ab12"}) for easy filtering."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        entry = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
        }
        head, *rest = message.split()
        pairs = [t.partition("=") for t in rest]
        if "." in head and rest and all(sep for _, sep, _ in pairs):
            entry["event"] = head
            entry["fields"] = {k: v for k, _, v in pairs}
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def _file_handler(path: Path, level: int) -> RotatingFileHandler:
    handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    return handler


def setup_logging(level: str = "INFO", log_dir: str = "logs") -> None:
    """Console (plain text) always; with `log_dir`, also JSON-lines app.log (all), error.log (ERROR+), audit.log."""
    root = logging.getLogger()
    if getattr(root, "_app_configured", False):  # --reload / repeated imports must not stack handlers
        return
    root._app_configured = True  # type: ignore[attr-defined]
    root.setLevel(level.upper())

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter(FORMAT))
    root.addHandler(console)

    if not log_dir:
        return
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    root.addHandler(_file_handler(directory / "app.log", logging.NOTSET))
    root.addHandler(_file_handler(directory / "error.log", logging.ERROR))
    # Audit events propagate to the root handlers too; this file is just the filtered business trail.
    logging.getLogger("audit").addHandler(_file_handler(directory / "audit.log", logging.NOTSET))
