/** A fixed, isolated Python bootstrap and host-selected worker launch grants. */
export function workerArgv(config, command) {
  // The expected parent is the trusted Gateway process. Check both sides of
  // prctl so an already orphaned child cannot continue into trusted imports.
  const bootstrap = [
    "import ctypes, os, signal, sys",
    "expected_parent = int(sys.argv.pop(1))",
    "if os.getppid() != expected_parent: sys.exit(125)",
    "libc = ctypes.CDLL(None, use_errno=True)",
    "if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0: sys.exit(125)",
    "if os.getppid() != expected_parent: sys.exit(125)",
    "sys.path.insert(0, sys.argv.pop(1))",
    "from yuanxingmu.worker import main",
    "main()",
  ].join("\n");
  // -I ignores cwd and Python environment injection. -B also prevents trusted
  // runtime snapshots from growing __pycache__ files despite isolated mode.
  return [config.python, "-I", "-B", "-c", bootstrap, String(process.pid), config.corePath,
    "--workspace", config.workspace, "--broker-socket", config.brokerSocket, "--bwrap", config.bwrap,
    "--readonly", config.corePath, "--env-json", JSON.stringify({ PYTHONPATH: config.corePath }),
    "--", ...command];
}
