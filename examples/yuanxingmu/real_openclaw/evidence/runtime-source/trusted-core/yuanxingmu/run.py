"""Trusted operator entry point. Configuration is never accepted over worker RPC."""
import json
from pathlib import Path
import signal
import tempfile

from .broker import Broker, Destination, Resource
from .worker import start, stop


def load_policy(path: Path):
    path = path.resolve(strict=True)
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != {"resources", "destinations"}:
        raise ValueError("policy_requires_exact_resources_and_destinations_fields")
    resources, destinations = {}, {}
    for name, item in config["resources"].items():
        if set(item) != {"path", "labels"} or not isinstance(item["labels"], list):
            raise ValueError("resource_requires_path_and_labels")
        resources[name] = Resource((path.parent / item["path"]).resolve(strict=True), tuple(item["labels"]))
    for name, item in config["destinations"].items():
        if set(item) not in ({"url", "labels"}, {"url", "labels", "headers"}) or not isinstance(item["labels"], list):
            raise ValueError("destination_requires_url_and_labels")
        destinations[name] = Destination(item["url"], tuple(item["labels"]), item.get("headers", {}))
    return resources, destinations


def run_command(*, policy: Path, state: Path, task: str, new_task: bool, workspace: Path,
                command: list[str], bwrap: Path | None = None) -> int:
    resources, destinations = load_policy(policy)
    package = Path(__file__).resolve().parent
    with Broker(state, resources, destinations) as broker, tempfile.TemporaryDirectory(prefix="yxm-") as sockets:
        if new_task:
            broker.create_task(task_id=task)
        workspace = broker.bind_workspace(task, workspace)
        endpoint = broker.serve(task, Path(sockets) / "broker.sock")
        process = start(command=command, workspace=workspace, broker_socket=endpoint,
                        readonly_paths=[package], env={"PYTHONPATH": str(package.parent)}, bwrap=bwrap)
        old_signals = {}

        def interrupt(signum, frame):
            stop(process)
            raise SystemExit(128 + signum)

        for signum in (signal.SIGINT, signal.SIGTERM):
            old_signals[signum] = signal.signal(signum, interrupt)
        try:
            return process.wait()
        finally:
            stop(process)
            for signum, handler in old_signals.items():
                signal.signal(signum, handler)
